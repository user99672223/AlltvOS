// IOKitExplorerModule.swift
// Walks the IORegistry across all planes to enumerate hardware services,
// device properties, and user client accessibility. Reveals the full
// device tree visible to a sandboxed app — GPUs, thermal sensors, storage
// controllers, USB devices, and which IOServices can be opened.
//
// IOKit headers are not part of the tvOS SDK, so all IOKit entry points
// are resolved at runtime via dlsym.

import Foundation

final class IOKitExplorerModule: ReconModule {
    let name = "IOKitExplorer"
    let timeout: TimeInterval = 120

    func run(engine: ReconEngine) {
        guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW) else {
            engine.reportError(module: name, key: "iokit_framework", error: "dlopen failed")
            return
        }
        defer { dlclose(handle) }

        do {
            let iokit = try IOKitExplorerSymbols(handle: handle)
            let planes = ["IOService", "IODeviceTree", "IOPower", "IOUSB", "IOFireWire", "IOAudio"]
            for plane in planes {
                walkPlane(plane, engine: engine, iokit: iokit)
            }
            probeSpecificServices(engine: engine, iokit: iokit)
        } catch {
            engine.reportError(module: name, key: "iokit_symbols", error: "\(error)")
        }
    }

    // MARK: - Walk an IOKit plane

    private func walkPlane(_ plane: String, engine: ReconEngine, iokit: IOKitExplorerSymbols) {
        let rootEntry = iokit.registryGetRootEntry(iokit.masterPort)
        guard rootEntry != 0 else {
            engine.reportError(module: name, key: "plane.\(plane)", error: "cannot get root entry")
            return
        }

        var count = 0
        walkEntry(rootEntry, plane: plane, depth: 0, maxDepth: 8, engine: engine, iokit: iokit, count: &count)
        engine.report(module: name, key: "plane.\(plane).total_entries", value: count)
        _ = iokit.objectRelease(rootEntry)
    }

    private func walkEntry(_ entry: io_registry_entry_t, plane: String,
                           depth: Int, maxDepth: Int, engine: ReconEngine,
                           iokit: IOKitExplorerSymbols, count: inout Int) {
        guard depth <= maxDepth else { return }
        count += 1

        var info: [String: Any] = [:]

        var className = [CChar](repeating: 0, count: 256)
        if iokit.objectGetClass(entry, &className) == KERN_SUCCESS {
            info["class"] = String(cString: className)
        }

        var nameBuf = [CChar](repeating: 0, count: 256)
        if iokit.registryEntryGetNameInPlane(entry, plane, &nameBuf) == KERN_SUCCESS {
            info["name"] = String(cString: nameBuf)
        }

        var locBuf = [CChar](repeating: 0, count: 256)
        if iokit.registryEntryGetLocationInPlane(entry, plane, &locBuf) == KERN_SUCCESS {
            info["location"] = String(cString: locBuf)
        }

        var entryID: UInt64 = 0
        if iokit.registryEntryGetRegistryEntryID(entry, &entryID) == KERN_SUCCESS {
            info["registryEntryID"] = entryID
        }

        var pathBuf = [CChar](repeating: 0, count: 1024)
        if iokit.registryEntryGetPath(entry, plane, &pathBuf) == KERN_SUCCESS {
            info["path"] = String(cString: pathBuf)
        }

        var busy: UInt32 = 0
        if iokit.serviceGetBusyState(entry, &busy) == KERN_SUCCESS {
            info["busyState"] = busy
        }

        let (propKr, props) = iokit.copyProperties(of: entry)
        if propKr == KERN_SUCCESS, let props = props {
            var serializedProps: [String: Any] = [:]
            for (key, value) in props {
                if let s = value as? String {
                    serializedProps[key] = s
                } else if let n = value as? NSNumber {
                    serializedProps[key] = n
                } else if let b = value as? Bool {
                    serializedProps[key] = b
                } else if let d = value as? Data {
                    serializedProps[key] = d.count <= 256 ? d.base64EncodedString() : "Data[\(d.count) bytes]"
                } else if let arr = value as? [Any] {
                    if let jsonData = try? JSONSerialization.data(withJSONObject: arr, options: []),
                       jsonData.count < 1024,
                       let jsonStr = String(data: jsonData, encoding: .utf8) {
                        serializedProps[key] = jsonStr
                    } else {
                        serializedProps[key] = "Array[\(arr.count)]"
                    }
                } else if let dict = value as? [String: Any] {
                    if let jsonData = try? JSONSerialization.data(withJSONObject: dict, options: []),
                       jsonData.count < 1024,
                       let jsonStr = String(data: jsonData, encoding: .utf8) {
                        serializedProps[key] = jsonStr
                    } else {
                        serializedProps[key] = "Dict[\(dict.count)]"
                    }
                } else {
                    serializedProps[key] = "\(value)"
                }
            }
            if !serializedProps.isEmpty {
                info["properties"] = serializedProps
            }
            info["property_count"] = props.count
        }

        var childIter: io_iterator_t = 0
        if iokit.registryEntryGetChildIterator(entry, plane, &childIter) == KERN_SUCCESS {
            var childCount = 0
            var child = iokit.iteratorNext(childIter)
            while child != 0 {
                childCount += 1
                _ = iokit.objectRelease(child)
                child = iokit.iteratorNext(childIter)
            }
            info["childCount"] = childCount
            _ = iokit.objectRelease(childIter)
        }

        let classStr = info["class"] as? String ?? ""
        let isInteresting = isInterestingClass(classStr)
        if depth <= 4 || isInteresting {
            engine.report(module: name, key: "iokit.\(plane).\(count)", value: info)
        }

        if isInteresting {
            tryServiceOpen(entry: entry, className: classStr, engine: engine, iokit: iokit)
        }

        var iter: io_iterator_t = 0
        if iokit.registryEntryGetChildIterator(entry, plane, &iter) == KERN_SUCCESS {
            var child = iokit.iteratorNext(iter)
            while child != 0 {
                walkEntry(child, plane: plane, depth: depth + 1,
                         maxDepth: maxDepth, engine: engine, iokit: iokit, count: &count)
                _ = iokit.objectRelease(child)
                child = iokit.iteratorNext(iter)
            }
            _ = iokit.objectRelease(iter)
        }
    }

    private func isInterestingClass(_ className: String) -> Bool {
        let patterns = [
            "AppleSEP", "AppleARMIODevice", "AppleARMPE", "AppleT",
            "AppleDisplay", "AppleUSB", "AppleAVE", "AppleCamIn",
            "AGX", "IOGPU", "AppleM", "AppleARMThermal", "coretemp",
            "mDNS", "AppleBluetooth", "AppleARMPMU", "IOHIDSystem",
            "AppleEmbeddedNVMe", "AppleANS", "IOTimeSyncClock",
            "AppleSMC", "IOService", "AppleKeyStore",
        ]
        return patterns.contains { className.contains($0) }
    }

    private func tryServiceOpen(entry: io_registry_entry_t, className: String,
                                engine: ReconEngine, iokit: IOKitExplorerSymbols) {
        var connect: io_connect_t = 0
        let kr = iokit.serviceOpen(entry, mach_task_self_, 0, &connect)
        if kr == KERN_SUCCESS {
            engine.report(module: name, key: "iokit.open.\(className)", value: [
                "result": "success",
                "connect": String(format: "0x%x", connect),
            ])
            _ = iokit.serviceClose(connect)
        } else {
            engine.report(module: name, key: "iokit.open.\(className)", value: [
                "result": "denied",
                "kern_return": kr,
            ])
        }
    }

    // MARK: - Specific services

    private func probeSpecificServices(engine: ReconEngine, iokit: IOKitExplorerSymbols) {
        let serviceNames = [
            "AppleSEPManager", "AppleARMIODevice", "AppleARMPE",
            "AppleDisplay", "AppleUSBDevice", "AppleAVE2Driver",
            "AGXAccelerator", "IOGPUDevice", "AppleARMThermalSensor",
            "IOHIDSystem", "AppleEmbeddedNVMeController",
            "IOTimeSyncClockManager", "AppleKeyStore",
            "AppleSMC", "AppleARMPMU",
        ]

        for svcName in serviceNames {
            guard let matching = iokit.matchingDictionary(for: svcName) else {
                engine.report(module: name, key: "iokit.specific.\(svcName)", value: [
                    "found": false, "error": "no matching dict",
                ] as [String: Any])
                continue
            }
            var iter: io_iterator_t = 0
            let kr = iokit.getMatchingServices(iokit.masterPort, matching, &iter)
            if kr == KERN_SUCCESS {
                var svc = iokit.iteratorNext(iter)
                var found = 0
                while svc != 0 {
                    found += 1

                    let (propKr, props) = iokit.copyProperties(of: svc)
                    if propKr == KERN_SUCCESS, let props = props {
                        var serialized: [String: Any] = [:]
                        for (key, value) in props {
                            if let s = value as? String { serialized[key] = s }
                            else if let n = value as? NSNumber { serialized[key] = n }
                            else if let d = value as? Data {
                                serialized[key] = d.count <= 256 ? d.base64EncodedString() : "Data[\(d.count)]"
                            } else {
                                serialized[key] = "\(value)"
                            }
                        }
                        engine.report(module: name, key: "iokit.specific.\(svcName).\(found)", value: serialized)
                    }

                    _ = iokit.objectRelease(svc)
                    svc = iokit.iteratorNext(iter)
                }
                _ = iokit.objectRelease(iter)
                engine.report(module: name, key: "iokit.specific.\(svcName).count", value: found)
            } else {
                engine.report(module: name, key: "iokit.specific.\(svcName)", value: [
                    "found": false,
                    "error": kr,
                ] as [String: Any])
            }
        }
    }
}

// MARK: - IOKit Symbol Resolution

private enum IOKitExplorerSymbolError: Error {
    case notFound(String)
}

private struct IOKitExplorerSymbols {
    typealias RegistryGetRootEntryFn = @convention(c) (mach_port_t) -> io_registry_entry_t
    typealias ObjectReleaseFn = @convention(c) (io_object_t) -> kern_return_t
    typealias ObjectGetClassFn = @convention(c) (io_object_t, UnsafeMutablePointer<CChar>) -> kern_return_t
    typealias RegistryEntryGetNameInPlaneFn = @convention(c) (io_registry_entry_t, UnsafePointer<CChar>, UnsafeMutablePointer<CChar>) -> kern_return_t
    typealias RegistryEntryGetLocationInPlaneFn = @convention(c) (io_registry_entry_t, UnsafePointer<CChar>, UnsafeMutablePointer<CChar>) -> kern_return_t
    typealias RegistryEntryGetRegistryEntryIDFn = @convention(c) (io_registry_entry_t, UnsafeMutablePointer<UInt64>) -> kern_return_t
    typealias RegistryEntryGetPathFn = @convention(c) (io_registry_entry_t, UnsafePointer<CChar>, UnsafeMutablePointer<CChar>) -> kern_return_t
    typealias ServiceGetBusyStateFn = @convention(c) (io_service_t, UnsafeMutablePointer<UInt32>) -> kern_return_t
    typealias RegistryEntryCreatePropertiesFn = @convention(c) (io_registry_entry_t, UnsafeMutablePointer<UnsafeMutableRawPointer?>, UnsafeRawPointer?, UInt32) -> kern_return_t
    typealias RegistryEntryGetChildIteratorFn = @convention(c) (io_registry_entry_t, UnsafePointer<CChar>, UnsafeMutablePointer<io_iterator_t>) -> kern_return_t
    typealias IteratorNextFn = @convention(c) (io_iterator_t) -> io_object_t
    typealias ServiceOpenFn = @convention(c) (io_service_t, mach_port_t, UInt32, UnsafeMutablePointer<io_connect_t>) -> kern_return_t
    typealias ServiceCloseFn = @convention(c) (io_connect_t) -> kern_return_t
    typealias ServiceMatchingFn = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutableRawPointer?
    typealias GetMatchingServicesFn = @convention(c) (mach_port_t, UnsafeMutableRawPointer?, UnsafeMutablePointer<io_iterator_t>) -> kern_return_t

    let masterPort: mach_port_t = 0

    let registryGetRootEntry: RegistryGetRootEntryFn
    let objectRelease: ObjectReleaseFn
    let objectGetClass: ObjectGetClassFn
    let registryEntryGetNameInPlane: RegistryEntryGetNameInPlaneFn
    let registryEntryGetLocationInPlane: RegistryEntryGetLocationInPlaneFn
    let registryEntryGetRegistryEntryID: RegistryEntryGetRegistryEntryIDFn
    let registryEntryGetPath: RegistryEntryGetPathFn
    let serviceGetBusyState: ServiceGetBusyStateFn
    let registryEntryCreateProperties: RegistryEntryCreatePropertiesFn
    let registryEntryGetChildIterator: RegistryEntryGetChildIteratorFn
    let iteratorNext: IteratorNextFn
    let serviceOpen: ServiceOpenFn
    let serviceClose: ServiceCloseFn
    let serviceMatching: ServiceMatchingFn
    let getMatchingServices: GetMatchingServicesFn

    init(handle: UnsafeMutableRawPointer) throws {
        registryGetRootEntry = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryGetRootEntry"), to: RegistryGetRootEntryFn.self)
        objectRelease = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOObjectRelease"), to: ObjectReleaseFn.self)
        objectGetClass = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOObjectGetClass"), to: ObjectGetClassFn.self)
        registryEntryGetNameInPlane = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryGetNameInPlane"), to: RegistryEntryGetNameInPlaneFn.self)
        registryEntryGetLocationInPlane = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryGetLocationInPlane"), to: RegistryEntryGetLocationInPlaneFn.self)
        registryEntryGetRegistryEntryID = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryGetRegistryEntryID"), to: RegistryEntryGetRegistryEntryIDFn.self)
        registryEntryGetPath = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryGetPath"), to: RegistryEntryGetPathFn.self)
        serviceGetBusyState = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOServiceGetBusyState"), to: ServiceGetBusyStateFn.self)
        registryEntryCreateProperties = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryCreateCFProperties"), to: RegistryEntryCreatePropertiesFn.self)
        registryEntryGetChildIterator = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IORegistryEntryGetChildIterator"), to: RegistryEntryGetChildIteratorFn.self)
        iteratorNext = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOIteratorNext"), to: IteratorNextFn.self)
        serviceOpen = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOServiceOpen"), to: ServiceOpenFn.self)
        serviceClose = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOServiceClose"), to: ServiceCloseFn.self)
        serviceMatching = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOServiceMatching"), to: ServiceMatchingFn.self)
        getMatchingServices = try unsafeBitCast(IOKitExplorerSymbols.sym(handle, "IOServiceGetMatchingServices"), to: GetMatchingServicesFn.self)
    }

    func matchingDictionary(for className: String) -> UnsafeMutableRawPointer? {
        return className.withCString { serviceMatching($0) }
    }

    func copyProperties(of entry: io_registry_entry_t) -> (kern_return_t, [String: Any]?) {
        var raw: UnsafeMutableRawPointer? = nil
        let status = registryEntryCreateProperties(entry, &raw, nil, 0)
        guard status == KERN_SUCCESS, let rawDict = raw else {
            return (status, nil)
        }
        let cfDict = Unmanaged<CFMutableDictionary>.fromOpaque(UnsafeRawPointer(rawDict)).takeRetainedValue()
        return (status, cfDict as? [String: Any])
    }

    private static func sym(_ handle: UnsafeMutableRawPointer, _ name: String) throws -> UnsafeMutableRawPointer {
        guard let pointer = dlsym(handle, name) else {
            throw IOKitExplorerSymbolError.notFound(name)
        }
        return pointer
    }
}
