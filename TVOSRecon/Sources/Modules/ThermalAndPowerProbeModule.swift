// ThermalAndPowerProbeModule: Reads thermal state, low-power mode, and IOKit thermal/power sensors.
// Reveals thermal throttling state and power management configuration on Apple TV.

import Foundation

final class ThermalAndPowerProbeModule: ReconModule {
    let name = "ThermalAndPowerProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeThermalState(engine: engine)
        probeLowPowerMode(engine: engine)

        // IOKit's headers are not in the tvOS SDK, so its entry points are resolved with dlsym.
        guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW) else {
            engine.reportError(module: name, key: "iokit_framework", error: "dlopen failed: \(lastDLError())")
            return
        }
        defer { dlclose(handle) }

        do {
            let iokit = try IOKitSymbols(handle: handle)
            probeIOKitThermalSensors(engine: engine, iokit: iokit)
            probeIOKitPowerManagement(engine: engine, iokit: iokit)
        } catch {
            engine.reportError(module: name, key: "iokit_symbols", error: "\(error)")
        }
    }

    private func probeThermalState(engine: ReconEngine) {
        let info = ProcessInfo.processInfo
        let stateStr: String
        switch info.thermalState {
        case .nominal:  stateStr = "nominal"
        case .fair:     stateStr = "fair"
        case .serious:  stateStr = "serious"
        case .critical: stateStr = "critical"
        @unknown default: stateStr = "unknown(\(info.thermalState.rawValue))"
        }
        engine.report(module: name, key: "thermalState", value: stateStr)
        engine.report(module: name, key: "thermalState_rawValue", value: "\(info.thermalState.rawValue)")
    }

    private func probeLowPowerMode(engine: ReconEngine) {
        engine.report(module: name, key: "isLowPowerModeEnabled", value: "\(ProcessInfo.processInfo.isLowPowerModeEnabled)")
    }

    private func probeIOKitThermalSensors(engine: ReconEngine, iokit: IOKitSymbols) {
        let sensorClasses = [
            "IOHIDSensor",
            "AppleARMThermalSensor",
            "coretemp",
            "AppleARMThermal",
            "IOHIDEventService"
        ]

        for className in sensorClasses {
            guard let matching = iokit.matchingDictionary(for: className) else {
                engine.report(module: name, key: "thermal_class_\(className)", value: "no_matching_dict")
                continue
            }

            var iterator: io_iterator_t = 0
            // IOServiceGetMatchingServices consumes `matching`, so it is not released here.
            let kr = iokit.getMatchingServices(iokit.masterPort, matching, &iterator)
            guard kr == KERN_SUCCESS else {
                engine.reportError(module: name, key: "thermal_class_\(className)", error: "IOServiceGetMatchingServices failed: \(kr)")
                continue
            }
            defer { _ = iokit.objectRelease(iterator) }

            var entryCount = 0
            var entry = iokit.iteratorNext(iterator)
            while entry != 0 {
                defer {
                    _ = iokit.objectRelease(entry)
                    entry = iokit.iteratorNext(iterator)
                }
                entryCount += 1

                var nameBuffer = [CChar](repeating: 0, count: 128)
                _ = iokit.registryEntryGetName(entry, &nameBuffer)
                let entryName = String(cString: nameBuffer)

                let (propKr, properties) = iokit.copyProperties(of: entry)
                if propKr == KERN_SUCCESS, let dict = properties {
                    let interestingKeys = ["Temperature", "CurrentTemperature", "temperature",
                                           "PrimaryUsagePage", "PrimaryUsage", "Product",
                                           "SensorType", "Type", "Location"]
                    var sensorInfo: [String: String] = ["name": entryName]
                    for key in interestingKeys {
                        if let val = dict[key] {
                            sensorInfo[key] = "\(val)"
                        }
                    }
                    for (key, val) in dict {
                        let lk = key.lowercased()
                        if lk.contains("temp") || lk.contains("thermal") || lk.contains("power") || lk.contains("watt") {
                            sensorInfo[key] = "\(val)"
                        }
                    }
                    engine.reportBulk(module: name, key: "thermal_sensor_\(className)_\(entryCount)", value: sensorInfo)
                } else {
                    engine.report(module: name, key: "thermal_sensor_\(className)_\(entryCount)", value: "name=\(entryName), props_failed=\(propKr)")
                }
            }
            engine.report(module: name, key: "thermal_class_\(className)_count", value: "\(entryCount)")
        }
    }

    private func probeIOKitPowerManagement(engine: ReconEngine, iokit: IOKitSymbols) {
        let pmClasses = [
            "AppleARMPMU",
            "IOPMPowerSource",
            "AppleSMC",
            "IOPMrootDomain",
            "AppleARMBacklight"
        ]

        for className in pmClasses {
            guard let matching = iokit.matchingDictionary(for: className) else {
                engine.report(module: name, key: "power_class_\(className)", value: "no_matching_dict")
                continue
            }

            var iterator: io_iterator_t = 0
            let kr = iokit.getMatchingServices(iokit.masterPort, matching, &iterator)
            guard kr == KERN_SUCCESS else {
                engine.reportError(module: name, key: "power_class_\(className)", error: "IOServiceGetMatchingServices failed: \(kr)")
                continue
            }
            defer { _ = iokit.objectRelease(iterator) }

            var entryCount = 0
            var entry = iokit.iteratorNext(iterator)
            while entry != 0 {
                defer {
                    _ = iokit.objectRelease(entry)
                    entry = iokit.iteratorNext(iterator)
                }
                entryCount += 1

                var nameBuffer = [CChar](repeating: 0, count: 128)
                _ = iokit.registryEntryGetName(entry, &nameBuffer)
                let entryName = String(cString: nameBuffer)

                let (propKr, properties) = iokit.copyProperties(of: entry)
                if propKr == KERN_SUCCESS, let dict = properties {
                    var info: [String: String] = ["name": entryName]
                    for (key, val) in dict {
                        if let s = val as? String {
                            info[key] = s
                        } else if let n = val as? NSNumber {
                            info[key] = n.stringValue
                        } else if let d = val as? Data {
                            info[key] = "data[\(d.count) bytes]"
                        } else if let b = val as? Bool {
                            info[key] = "\(b)"
                        } else {
                            info[key] = "\(val)"
                        }
                    }
                    engine.reportBulk(module: name, key: "power_\(className)_\(entryCount)", value: info)
                } else {
                    engine.report(module: name, key: "power_\(className)_\(entryCount)", value: "name=\(entryName), props_failed=\(propKr)")
                }
            }
            engine.report(module: name, key: "power_class_\(className)_count", value: "\(entryCount)")
        }

        if let matching = iokit.matchingDictionary(for: "AppleFanCtrl") {
            var iterator: io_iterator_t = 0
            let kr = iokit.getMatchingServices(iokit.masterPort, matching, &iterator)
            if kr == KERN_SUCCESS {
                var count = 0
                var entry = iokit.iteratorNext(iterator)
                while entry != 0 {
                    count += 1
                    _ = iokit.objectRelease(entry)
                    entry = iokit.iteratorNext(iterator)
                }
                _ = iokit.objectRelease(iterator)
                engine.report(module: name, key: "fan_controller_count", value: "\(count)")
            } else {
                engine.report(module: name, key: "fan_controller", value: "not_found")
            }
        }
    }
}

// MARK: - IOKit access through dlsym

private enum IOKitLookupError: Error, CustomStringConvertible {
    case notFound(String)

    var description: String {
        switch self {
        case .notFound(let symbol):
            return "\(symbol) not found via dlsym"
        }
    }
}

private func lastDLError() -> String {
    guard let message = dlerror() else { return "unknown" }
    return String(cString: message)
}

/// The IOKit functions this module uses, resolved from the IOKit image. They stay valid only
/// while that handle is open, which `run(engine:)` guarantees for the duration of the probes.
private struct IOKitSymbols {
    typealias ServiceMatchingFn = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutableRawPointer?
    typealias GetMatchingServicesFn = @convention(c) (mach_port_t, UnsafeMutableRawPointer?, UnsafeMutablePointer<io_iterator_t>) -> kern_return_t
    typealias IteratorNextFn = @convention(c) (io_iterator_t) -> io_object_t
    typealias ObjectReleaseFn = @convention(c) (io_object_t) -> kern_return_t
    typealias RegistryEntryGetNameFn = @convention(c) (io_registry_entry_t, UnsafeMutablePointer<CChar>) -> kern_return_t
    typealias RegistryEntryCreatePropertiesFn = @convention(c) (io_registry_entry_t, UnsafeMutablePointer<UnsafeMutableRawPointer?>, UnsafeRawPointer?, IOOptionBits) -> kern_return_t

    /// Stands in for kIOMasterPortDefault, which is MACH_PORT_NULL.
    let masterPort: mach_port_t = 0

    let serviceMatching: ServiceMatchingFn
    let getMatchingServices: GetMatchingServicesFn
    let iteratorNext: IteratorNextFn
    let objectRelease: ObjectReleaseFn
    let registryEntryGetName: RegistryEntryGetNameFn
    let registryEntryCreateProperties: RegistryEntryCreatePropertiesFn

    init(handle: UnsafeMutableRawPointer) throws {
        serviceMatching = try unsafeBitCast(IOKitSymbols.symbol(handle, "IOServiceMatching"), to: ServiceMatchingFn.self)
        getMatchingServices = try unsafeBitCast(IOKitSymbols.symbol(handle, "IOServiceGetMatchingServices"), to: GetMatchingServicesFn.self)
        iteratorNext = try unsafeBitCast(IOKitSymbols.symbol(handle, "IOIteratorNext"), to: IteratorNextFn.self)
        objectRelease = try unsafeBitCast(IOKitSymbols.symbol(handle, "IOObjectRelease"), to: ObjectReleaseFn.self)
        registryEntryGetName = try unsafeBitCast(IOKitSymbols.symbol(handle, "IORegistryEntryGetName"), to: RegistryEntryGetNameFn.self)
        registryEntryCreateProperties = try unsafeBitCast(IOKitSymbols.symbol(handle, "IORegistryEntryCreateCFProperties"), to: RegistryEntryCreatePropertiesFn.self)
    }

    /// IOServiceMatching(className). The dictionary is +1 and must be passed to
    /// `getMatchingServices` exactly once, because that call consumes it.
    func matchingDictionary(for className: String) -> UnsafeMutableRawPointer? {
        return className.withCString { serviceMatching($0) }
    }

    /// Reads an entry's properties as a Swift dictionary. The out-parameter is a +1
    /// CFMutableDictionary, so ownership is taken here and ARC releases it.
    func copyProperties(of entry: io_registry_entry_t) -> (kern_return_t, [String: Any]?) {
        var raw: UnsafeMutableRawPointer? = nil
        // A nil allocator selects the default allocator, same as kCFAllocatorDefault.
        let status = registryEntryCreateProperties(entry, &raw, nil, 0)
        guard status == KERN_SUCCESS, let rawDict = raw else {
            return (status, nil)
        }
        let cfDict = Unmanaged<CFMutableDictionary>.fromOpaque(UnsafeRawPointer(rawDict)).takeRetainedValue()
        return (status, cfDict as? [String: Any])
    }

    private static func symbol(_ handle: UnsafeMutableRawPointer, _ name: String) throws -> UnsafeMutableRawPointer {
        guard let pointer = dlsym(handle, name) else {
            throw IOKitLookupError.notFound(name)
        }
        return pointer
    }
}
