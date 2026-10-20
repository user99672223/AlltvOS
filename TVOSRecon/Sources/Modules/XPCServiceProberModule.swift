// XPCServiceProberModule.swift
// Enumerates XPC services from LaunchDaemons plists, XPCServices directories, and
// LaunchAgents. Attempts xpc_connection_create_mach_service and bootstrap_look_up
// for each discovered service to map the accessible IPC surface.

import Foundation

final class XPCServiceProberModule: ReconModule {
    let name = "XPCServiceProber"
    let timeout: TimeInterval = 120

    func run(engine: ReconEngine) {
        var discoveredServices = Set<String>()

        // --- Walk LaunchDaemons plists for MachServices keys ---
        discoverFromPlists(
            directory: "/System/Library/LaunchDaemons",
            engine: engine,
            discovered: &discoveredServices
        )

        // --- Walk XPCServices ---
        discoverXPCServiceBundles(
            directory: "/System/Library/XPCServices",
            engine: engine,
            discovered: &discoveredServices
        )

        // --- Walk LaunchAgents ---
        discoverFromPlists(
            directory: "/System/Library/LaunchAgents",
            engine: engine,
            discovered: &discoveredServices
        )

        // --- Check launchd.db ---
        discoverFromPlists(
            directory: "/private/var/db/launchd.db",
            engine: engine,
            discovered: &discoveredServices
        )

        engine.report(module: name, key: "total_discovered_services", value: discoveredServices.count)

        // --- Try xpc_connection_create_mach_service for discovered services ---
        // Limit to first 200 to avoid excessive runtime
        let servicesToProbe = Array(discoveredServices.prefix(200))
        for svc in servicesToProbe {
            probeXPCService(serviceName: svc, engine: engine)
        }

        // --- bootstrap_look_up for well-known services ---
        let wellKnownServices: [String] = [
            "com.apple.springboard",
            "com.apple.backboardd",
            "com.apple.frontboard",
            "com.apple.lsd",
            "com.apple.iohideventsystem",
            "com.apple.mobilegestalt.xpc",
            "com.apple.securityd",
            "com.apple.containermanagerd",
            "com.apple.sandboxd",
            "com.apple.symptomsd",
            "com.apple.syslogd",
            "com.apple.cfprefsd.daemon",
            "com.apple.PowerManagement.control",
            "com.apple.mediaserverd",
            "com.apple.coremedia.endpoint.xpc",
            "com.apple.tvremoted",
            "com.apple.PineBoard",
            "com.apple.nfcd",
            "com.apple.wifid",
            "com.apple.bluetoothd",
            "com.apple.locationd",
            "com.apple.networkd",
            "com.apple.mDNSResponder",
            "com.apple.runningboard",
            "com.apple.apsd",
            "com.apple.notifyd",
            "com.apple.logd",
            "com.apple.coreduetd",
            "com.apple.usermanagerd",
            "com.apple.thermalmonitord",
            "com.apple.iokit.IOHIDSystem"
        ]

        for svc in wellKnownServices {
            bootstrapLookup(serviceName: svc, engine: engine)
            if !discoveredServices.contains(svc) {
                probeXPCService(serviceName: svc, engine: engine)
            }
        }
    }

    private func discoverFromPlists(directory: String, engine: ReconEngine, discovered: inout Set<String>) {
        let fm = FileManager.default
        guard fm.isReadableFile(atPath: directory) else {
            engine.report(module: name, key: "plist_dir_access", value: [
                "path": directory, "readable": false
            ] as [String: Any])
            return
        }

        do {
            let items = try fm.contentsOfDirectory(atPath: directory)
            var plistCount = 0
            for item in items {
                guard item.hasSuffix(".plist") else { continue }
                let fullPath = (directory as NSString).appendingPathComponent(item)
                plistCount += 1

                do {
                    let data = try Data(contentsOf: URL(fileURLWithPath: fullPath))
                    if let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                        // Look for MachServices key
                        if let machServices = plist["MachServices"] as? [String: Any] {
                            for (serviceName, _) in machServices {
                                discovered.insert(serviceName)
                                engine.report(module: name, key: "discovered_mach_service", value: [
                                    "service": serviceName,
                                    "source": fullPath
                                ] as [String: Any])
                            }
                        }
                        // Also check Label
                        if let label = plist["Label"] as? String {
                            discovered.insert(label)
                        }
                    }
                } catch {
                    engine.reportError(module: name, key: "plist_parse_error", error: "\(fullPath): \(error.localizedDescription)")
                }
            }
            engine.report(module: name, key: "plist_dir_scan", value: [
                "path": directory, "plists_found": plistCount, "services_found": discovered.count
            ] as [String: Any])
        } catch {
            engine.reportError(module: name, key: "plist_dir_error", error: "\(directory): \(error.localizedDescription)")
        }
    }

    private func discoverXPCServiceBundles(directory: String, engine: ReconEngine, discovered: inout Set<String>) {
        let fm = FileManager.default
        guard fm.isReadableFile(atPath: directory) else {
            engine.report(module: name, key: "xpc_dir_access", value: [
                "path": directory, "readable": false
            ] as [String: Any])
            return
        }

        do {
            let items = try fm.contentsOfDirectory(atPath: directory)
            for item in items {
                if item.hasSuffix(".xpc") {
                    let bundleName = (item as NSString).deletingPathExtension
                    discovered.insert(bundleName)
                    engine.report(module: name, key: "discovered_xpc_bundle", value: [
                        "bundle": item, "inferred_service": bundleName, "source": directory
                    ] as [String: Any])

                    // Try reading the bundle's Info.plist for the real service name
                    let infoPlistPath = (directory as NSString)
                        .appendingPathComponent(item)
                        .appending("/Contents/Info.plist")
                    if let data = try? Data(contentsOf: URL(fileURLWithPath: infoPlistPath)),
                       let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
                       let bundleId = plist["CFBundleIdentifier"] as? String {
                        discovered.insert(bundleId)
                        engine.report(module: name, key: "xpc_bundle_id", value: [
                            "bundle": item, "bundle_id": bundleId
                        ] as [String: Any])
                    }
                }
            }
        } catch {
            engine.reportError(module: name, key: "xpc_dir_error", error: "\(directory): \(error.localizedDescription)")
        }
    }

    private func probeXPCService(serviceName: String, engine: ReconEngine) {
        // Try xpc_connection_create_mach_service
        // We use the C XPC API
        let connection = xpc_connection_create_mach_service(
            serviceName,
            nil, // target queue
            0    // flags (0 = client, XPC_CONNECTION_MACH_SERVICE_LISTENER = 1)
        )

        var connectionResult: [String: Any] = [
            "service": serviceName,
            "connection_created": true
        ]

        // Set up event handler and activate
        let semaphore = DispatchSemaphore(value: 0)
        var replyInfo: [String: Any]?

        xpc_connection_set_event_handler(connection) { event in
            let eventType = xpc_get_type(event)
            if eventType == XPC_TYPE_ERROR {
                if event == XPC_ERROR_CONNECTION_INVALID {
                    replyInfo = ["event": "connection_invalid"]
                } else if event == XPC_ERROR_CONNECTION_INTERRUPTED {
                    replyInfo = ["event": "connection_interrupted"]
                } else if event == XPC_ERROR_TERMINATION_IMMINENT {
                    replyInfo = ["event": "termination_imminent"]
                } else {
                    replyInfo = ["event": "unknown_error"]
                }
                semaphore.signal()
            } else if eventType == XPC_TYPE_DICTIONARY {
                replyInfo = ["event": "dictionary_received"]
                semaphore.signal()
            }
        }

        xpc_connection_resume(connection)

        // Send a minimal ping/hello dictionary
        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "operation", "ping")
        xpc_dictionary_set_int64(msg, "version", 1)

        xpc_connection_send_message_with_reply(connection, msg, nil) { reply in
            let replyType = xpc_get_type(reply)
            if replyType == XPC_TYPE_ERROR {
                if reply == XPC_ERROR_CONNECTION_INVALID {
                    replyInfo = ["reply": "connection_invalid"]
                } else if reply == XPC_ERROR_CONNECTION_INTERRUPTED {
                    replyInfo = ["reply": "connection_interrupted"]
                } else {
                    replyInfo = ["reply": "error"]
                }
            } else if replyType == XPC_TYPE_DICTIONARY {
                // Try to extract any reply info
                var replyDict: [String: Any] = ["reply": "dictionary"]
                if let desc = xpc_copy_description(reply) {
                    let descStr = String(cString: desc)
                    replyDict["description"] = String(descStr.prefix(200))
                    free(desc)
                }
                replyInfo = replyDict
            } else {
                replyInfo = ["reply": "unexpected_type"]
            }
            semaphore.signal()
        }

        // Wait up to 2 seconds for reply
        let waitResult = semaphore.wait(timeout: .now() + 2.0)
        if waitResult == .timedOut {
            connectionResult["reply"] = "timeout"
        } else if let info = replyInfo {
            connectionResult.merge(info) { _, new in new }
        }

        xpc_connection_cancel(connection)
        engine.report(module: name, key: "xpc_probe", value: connectionResult)
    }

    private func bootstrapLookup(serviceName: String, engine: ReconEngine) {
        // bootstrap_look_up via the bootstrap.h API
        // kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp)
        typealias BootstrapLookUpFunc = @convention(c) (mach_port_t, UnsafePointer<CChar>, UnsafeMutablePointer<mach_port_t>) -> kern_return_t

        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        guard let fnPtr = dlsym(handle, "bootstrap_look_up") else {
            engine.reportError(module: name, key: "bootstrap_look_up_\(serviceName)", error: "bootstrap_look_up not found via dlsym")
            return
        }

        let fn = unsafeBitCast(fnPtr, to: BootstrapLookUpFunc.self)
        var servicePort: mach_port_t = 0

        // Get the bootstrap port
        let bootstrapPort = bootstrap_port

        let kr = serviceName.withCString { cName -> kern_return_t in
            return fn(bootstrapPort, cName, &servicePort)
        }

        var result: [String: Any] = [
            "service": serviceName,
            "kern_return": kr,
            "success": kr == KERN_SUCCESS
        ]

        if kr == KERN_SUCCESS {
            result["port"] = servicePort
        } else {
            result["error_code"] = kr
            // Common bootstrap errors
            switch kr {
            case 1100: result["error_name"] = "BOOTSTRAP_NOT_PRIVILEGED"
            case 1101: result["error_name"] = "BOOTSTRAP_NAME_IN_USE"
            case 1102: result["error_name"] = "BOOTSTRAP_UNKNOWN_SERVICE"
            case 1103: result["error_name"] = "BOOTSTRAP_SERVICE_ACTIVE"
            case 1104: result["error_name"] = "BOOTSTRAP_BAD_COUNT"
            case 1105: result["error_name"] = "BOOTSTRAP_NO_MEMORY"
            case 1106: result["error_name"] = "BOOTSTRAP_NO_CHILDREN"
            default: result["error_name"] = "KERN_\(kr)"
            }
        }

        engine.report(module: name, key: "bootstrap_look_up", value: result)

        // Deallocate port if we got one
        if kr == KERN_SUCCESS && servicePort != 0 {
            mach_port_deallocate(mach_task_self_, servicePort)
        }
    }
}
