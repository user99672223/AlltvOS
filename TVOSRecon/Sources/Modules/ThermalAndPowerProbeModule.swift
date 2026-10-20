// ThermalAndPowerProbeModule: Reads thermal state, low-power mode, and IOKit thermal/power sensors.
// Reveals thermal throttling state and power management configuration on Apple TV.

import Foundation
#if canImport(IOKit)
import IOKit
#endif

final class ThermalAndPowerProbeModule: ReconModule {
    let name = "ThermalAndPowerProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeThermalState(engine: engine)
        probeLowPowerMode(engine: engine)
        probeIOKitThermalSensors(engine: engine)
        probeIOKitPowerManagement(engine: engine)
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

    private func probeIOKitThermalSensors(engine: ReconEngine) {
        let sensorClasses = [
            "IOHIDSensor",
            "AppleARMThermalSensor",
            "coretemp",
            "AppleARMThermal",
            "IOHIDEventService"
        ]

        for className in sensorClasses {
            guard let matching = IOServiceMatching(className) else {
                engine.report(module: name, key: "thermal_class_\(className)", value: "no_matching_dict")
                continue
            }

            var iterator: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator)
            guard kr == KERN_SUCCESS else {
                engine.reportError(module: name, key: "thermal_class_\(className)", error: "IOServiceGetMatchingServices failed: \(kr)")
                continue
            }
            defer { IOObjectRelease(iterator) }

            var entryCount = 0
            var entry = IOIteratorNext(iterator)
            while entry != 0 {
                defer {
                    IOObjectRelease(entry)
                    entry = IOIteratorNext(iterator)
                }
                entryCount += 1

                var nameBuffer = [CChar](repeating: 0, count: 128)
                IORegistryEntryGetName(entry, &nameBuffer)
                let entryName = String(cString: nameBuffer)

                var properties: Unmanaged<CFMutableDictionary>?
                let propKr = IORegistryEntryCreateCFProperties(entry, &properties, kCFAllocatorDefault, 0)
                if propKr == KERN_SUCCESS, let dict = properties?.takeRetainedValue() as? [String: Any] {
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

    private func probeIOKitPowerManagement(engine: ReconEngine) {
        let pmClasses = [
            "AppleARMPMU",
            "IOPMPowerSource",
            "AppleSMC",
            "IOPMrootDomain",
            "AppleARMBacklight"
        ]

        for className in pmClasses {
            guard let matching = IOServiceMatching(className) else {
                engine.report(module: name, key: "power_class_\(className)", value: "no_matching_dict")
                continue
            }

            var iterator: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator)
            guard kr == KERN_SUCCESS else {
                engine.reportError(module: name, key: "power_class_\(className)", error: "IOServiceGetMatchingServices failed: \(kr)")
                continue
            }
            defer { IOObjectRelease(iterator) }

            var entryCount = 0
            var entry = IOIteratorNext(iterator)
            while entry != 0 {
                defer {
                    IOObjectRelease(entry)
                    entry = IOIteratorNext(iterator)
                }
                entryCount += 1

                var nameBuffer = [CChar](repeating: 0, count: 128)
                IORegistryEntryGetName(entry, &nameBuffer)
                let entryName = String(cString: nameBuffer)

                var properties: Unmanaged<CFMutableDictionary>?
                let propKr = IORegistryEntryCreateCFProperties(entry, &properties, kCFAllocatorDefault, 0)
                if propKr == KERN_SUCCESS, let dict = properties?.takeRetainedValue() as? [String: Any] {
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

        if let matching = IOServiceMatching("AppleFanCtrl") {
            var iterator: io_iterator_t = 0
            let kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator)
            if kr == KERN_SUCCESS {
                var count = 0
                var entry = IOIteratorNext(iterator)
                while entry != 0 {
                    count += 1
                    IOObjectRelease(entry)
                    entry = IOIteratorNext(iterator)
                }
                IOObjectRelease(iterator)
                engine.report(module: name, key: "fan_controller_count", value: "\(count)")
            } else {
                engine.report(module: name, key: "fan_controller", value: "not_found")
            }
        }
    }
}
