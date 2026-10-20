// IOKitExplorerModule.swift
// Walks the IORegistry across all planes to enumerate hardware services,
// device properties, and user client accessibility. Reveals the full
// device tree visible to a sandboxed app — GPUs, thermal sensors, storage
// controllers, USB devices, and which IOServices can be opened.

import Foundation

final class IOKitExplorerModule: ReconModule {
    let name = "IOKitExplorer"
    let timeout: TimeInterval = 120

    // IOKit C functions accessed via bridging header
    func run(engine: ReconEngine) {
        let planes = ["IOService", "IODeviceTree", "IOPower", "IOUSB", "IOFireWire", "IOAudio"]
        for plane in planes {
            walkPlane(plane, engine: engine)
        }
        probeSpecificServices(engine: engine)
    }

    // MARK: - Walk an IOKit plane

    private func walkPlane(_ plane: String, engine: ReconEngine) {
        let rootEntry = IORegistryGetRootEntry(kIOMainPortDefault)
        guard rootEntry != MACH_PORT_NULL else {
            engine.reportError(module: name, key: "plane.\(plane)", error: "cannot get root entry")
            return
        }

        var count = 0
        walkEntry(rootEntry, plane: plane, path: "", depth: 0, maxDepth: 8, engine: engine, count: &count)
        engine.report(module: name, key: "plane.\(plane).total_entries", value: count)
        IOObjectRelease(rootEntry)
    }

    private func walkEntry(_ entry: io_registry_entry_t, plane: String, path: String,
                           depth: Int, maxDepth: Int, engine: ReconEngine, count: inout Int) {
        guard depth <= maxDepth else { return }
        count += 1

        var info: [String: Any] = [:]

        // Class name
        var className = [CChar](repeating: 0, count: 256)
        if IOObjectGetClass(entry, &className) == KERN_SUCCESS {
            info["class"] = String(cString: className)
        }

        // Name in plane
        var nameBuf = [CChar](repeating: 0, count: 256)
        if IORegistryEntryGetNameInPlane(entry, plane, &nameBuf) == KERN_SUCCESS {
            let n = String(cString: nameBuf)
            info["name"] = n
        }

        // Location in plane
        var locBuf = [CChar](repeating: 0, count: 256)
        if IORegistryEntryGetLocationInPlane(entry, plane, &locBuf) == KERN_SUCCESS {
            info["location"] = String(cString: locBuf)
        }

        // Registry entry ID
        var entryID: UInt64 = 0
        if IORegistryEntryGetRegistryEntryID(entry, &entryID) == KERN_SUCCESS {
            info["registryEntryID"] = entryID
        }

        // Path
        var pathBuf = [CChar](repeating: 0, count: 1024)
        if IORegistryEntryGetPath(entry, plane, &pathBuf) == KERN_SUCCESS {
            let p = String(cString: pathBuf)
            info["path"] = p
        }

        // Busy state
        var busy: UInt32 = 0
        if IOServiceGetBusyState(entry, &busy) == KERN_SUCCESS {
            info["busyState"] = busy
        }

        // Properties
        var propsRef: Unmanaged<CFMutableDictionary>?
        if IORegistryEntryCreateCFProperties(entry, &propsRef, kCFAllocatorDefault, 0) == KERN_SUCCESS,
           let props = propsRef?.takeRetainedValue() as? [String: Any] {
            // Serialize a subset of properties — skip very large data blobs
            var serializedProps: [String: Any] = [:]
            for (key, value) in props {
                if let s = value as? String {
                    serializedProps[key] = s
                } else if let n = value as? NSNumber {
                    serializedProps[key] = n
                } else if let b = value as? Bool {
                    serializedProps[key] = b
                } else if let d = value as? Data {
                    if d.count <= 256 {
                        serializedProps[key] = d.base64EncodedString()
                    } else {
                        serializedProps[key] = "Data[\(d.count) bytes]"
                    }
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

        // Count children
        var childIter: io_iterator_t = 0
        if IORegistryEntryGetChildIterator(entry, plane, &childIter) == KERN_SUCCESS {
            var childCount = 0
            var child = IOIteratorNext(childIter)
            while child != MACH_PORT_NULL {
                childCount += 1
                IOObjectRelease(child)
                child = IOIteratorNext(childIter)
            }
            info["childCount"] = childCount
            IOObjectRelease(childIter)
        }

        // Report if not too deep or if it's an interesting class
        let classStr = info["class"] as? String ?? ""
        let isInteresting = isInterestingClass(classStr)
        if depth <= 4 || isInteresting {
            engine.report(module: name, key: "iokit.\(plane).\(count)", value: info)
        }

        // Try IOServiceOpen
        if isInteresting {
            tryServiceOpen(entry: entry, className: classStr, engine: engine)
        }

        // Recurse children
        var iter: io_iterator_t = 0
        if IORegistryEntryGetChildIterator(entry, plane, &iter) == KERN_SUCCESS {
            var child = IOIteratorNext(iter)
            while child != MACH_PORT_NULL {
                walkEntry(child, plane: plane, path: path, depth: depth + 1,
                         maxDepth: maxDepth, engine: engine, count: &count)
                IOObjectRelease(child)
                child = IOIteratorNext(iter)
            }
            IOObjectRelease(iter)
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

    private func tryServiceOpen(entry: io_registry_entry_t, className: String, engine: ReconEngine) {
        var connect: io_connect_t = 0
        let kr = IOServiceOpen(entry, mach_task_self_, 0, &connect)
        if kr == KERN_SUCCESS {
            engine.report(module: name, key: "iokit.open.\(className)", value: [
                "result": "success",
                "connect": String(format: "0x%x", connect),
            ])
            IOServiceClose(connect)
        } else {
            engine.report(module: name, key: "iokit.open.\(className)", value: [
                "result": "denied",
                "kern_return": kr,
            ])
        }
    }

    // MARK: - Specific services

    private func probeSpecificServices(engine: ReconEngine) {
        let serviceNames = [
            "AppleSEPManager", "AppleARMIODevice", "AppleARMPE",
            "AppleDisplay", "AppleUSBDevice", "AppleAVE2Driver",
            "AGXAccelerator", "IOGPUDevice", "AppleARMThermalSensor",
            "IOHIDSystem", "AppleEmbeddedNVMeController",
            "IOTimeSyncClockManager", "AppleKeyStore",
            "AppleSMC", "AppleARMPMU",
        ]

        for svcName in serviceNames {
            let matching = IOServiceMatching(svcName)
            var iter: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iter)
            if kr == KERN_SUCCESS {
                var svc = IOIteratorNext(iter)
                var found = 0
                while svc != MACH_PORT_NULL {
                    found += 1

                    // Get all properties
                    var propsRef: Unmanaged<CFMutableDictionary>?
                    if IORegistryEntryCreateCFProperties(svc, &propsRef, kCFAllocatorDefault, 0) == KERN_SUCCESS,
                       let props = propsRef?.takeRetainedValue() as? [String: Any] {
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

                    IOObjectRelease(svc)
                    svc = IOIteratorNext(iter)
                }
                IOObjectRelease(iter)
                engine.report(module: name, key: "iokit.specific.\(svcName).count", value: found)
            } else {
                engine.report(module: name, key: "iokit.specific.\(svcName)", value: [
                    "found": false,
                    "error": kr,
                ])
            }
        }
    }
}
