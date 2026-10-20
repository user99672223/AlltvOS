// EntitlementCheckerModule.swift
// Dumps the full entitlements blob from the process via csops, parses the XML,
// probes for specific entitlement keys via SecTaskCopyValueForEntitlement,
// reads embedded.mobileprovision from the bundle, and decodes all code signing flags.

import Foundation
import Security

final class EntitlementCheckerModule: ReconModule {
    let name = "EntitlementChecker"
    let timeout: TimeInterval = 60

    // csops signature: int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
    private typealias CsopsFunc = @convention(c) (Int32, UInt32, UnsafeMutableRawPointer?, Int) -> Int32
    // SecTaskCopyValueForEntitlement signature
    private typealias SecTaskCreateFunc = @convention(c) (CFAllocator?, audit_token_t) -> AnyObject?
    private typealias SecTaskCopyEntitlementFunc = @convention(c) (AnyObject, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> AnyObject?

    func run(engine: ReconEngine) {
        dumpEntitlementsBlob(engine: engine)
        probeEntitlementKeys(engine: engine)
        parseMobileProvision(engine: engine)
        dumpCodeSigningFlags(engine: engine)
    }

    // MARK: - Entitlements Blob via csops

    private func dumpEntitlementsBlob(engine: ReconEngine) {
        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        guard let csopsPtr = dlsym(handle, "csops") else {
            engine.reportError(module: name, key: "csops_entitlements", error: "csops not found via dlsym")
            return
        }
        let csops = unsafeBitCast(csopsPtr, to: CsopsFunc.self)
        let pid = getpid()

        // CS_OPS_ENTITLEMENTS_BLOB = 7
        // First try with a large buffer
        let bufSize = 131072 // 128KB should be enough
        var buf = [UInt8](repeating: 0, count: bufSize)
        errno = 0
        let ret = csops(pid, 7, &buf, bufSize)

        if ret == 0 {
            // Blob format: uint32_t magic, uint32_t length, then XML/DER data
            // The magic for entitlements is 0xFADE7171
            var magic: UInt32 = 0
            var length: UInt32 = 0
            if buf.count >= 8 {
                magic = UInt32(buf[0]) << 24 | UInt32(buf[1]) << 16 | UInt32(buf[2]) << 8 | UInt32(buf[3])
                length = UInt32(buf[4]) << 24 | UInt32(buf[5]) << 16 | UInt32(buf[6]) << 8 | UInt32(buf[7])
            }

            engine.report(module: name, key: "entitlements_blob_header", value: [
                "magic": String(format: "0x%08x", magic),
                "length": length,
                "is_xml_format": magic == 0xFADE7171
            ] as [String: Any])

            // Extract XML portion (after 8-byte header)
            if length > 8 && length <= UInt32(bufSize) {
                let xmlData = Data(buf[8..<Int(length)])
                if let xmlStr = String(data: xmlData, encoding: .utf8) {
                    engine.report(module: name, key: "entitlements_xml_raw", value: xmlStr)

                    // Try to parse the plist
                    if let plistData = xmlStr.data(using: .utf8) {
                        do {
                            if let dict = try PropertyListSerialization.propertyList(
                                from: plistData, options: [], format: nil
                            ) as? [String: Any] {
                                for (key, val) in dict {
                                    engine.report(module: name, key: "entitlement", value: [
                                        "key": key,
                                        "value": "\(val)",
                                        "type": "\(type(of: val))"
                                    ] as [String: Any])
                                }
                                engine.report(module: name, key: "entitlements_count", value: dict.count)
                            }
                        } catch {
                            engine.reportError(module: name, key: "entitlements_parse", error: error.localizedDescription)
                        }
                    }
                } else {
                    // Might be DER-encoded instead of XML
                    engine.report(module: name, key: "entitlements_format", value: [
                        "format": "non-xml (possibly DER)",
                        "data_base64": xmlData.prefix(256).base64EncodedString()
                    ] as [String: Any])
                }
            }
        } else {
            engine.report(module: name, key: "csops_entitlements", value: [
                "success": false, "return": ret,
                "errno": Int(errno),
                "error": String(cString: strerror(errno))
            ] as [String: Any])
        }
    }

    // MARK: - Probe Specific Entitlement Keys

    private func probeEntitlementKeys(engine: ReconEngine) {
        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        // Try SecTaskCreateFromSelf
        let secTaskCreateFromSelfPtr = dlsym(handle, "SecTaskCreateFromSelf")
        let secTaskCopyValuePtr = dlsym(handle, "SecTaskCopyValueForEntitlement")

        engine.report(module: name, key: "SecTaskCreateFromSelf_available", value: secTaskCreateFromSelfPtr != nil)
        engine.report(module: name, key: "SecTaskCopyValueForEntitlement_available", value: secTaskCopyValuePtr != nil)

        let entitlementKeys: [String] = [
            "com.apple.security.app-sandbox",
            "com.apple.private.security.no-sandbox",
            "platform-application",
            "get-task-allow",
            "task_for_pid-allow",
            "com.apple.private.skip-library-validation",
            "com.apple.private.amfi.can-load-cdhash",
            "com.apple.private.memorystatus",
            "com.apple.private.kernel.override-cpumon",
            "keychain-access-groups",
            "application-identifier",
            "com.apple.developer.team-identifier",
            "com.apple.private.iokit.user-client-class",
            "com.apple.private.security.storage.AppBundles",
            "com.apple.private.security.storage.AppDataContainers",
            "com.apple.private.tcc.allow",
            "com.apple.private.tcc.manager",
            "com.apple.private.xpc.launchd.job-label",
            "com.apple.springboard.debugapplications",
            "com.apple.developer.associated-domains",
            "com.apple.developer.networking.networkextension",
            "com.apple.developer.kernel.extended-virtual-addressing",
            "com.apple.developer.kernel.increased-memory-limit",
            "com.apple.security.application-groups",
            "com.apple.developer.icloud-container-identifiers",
            "aps-environment",
            "com.apple.developer.default-data-protection"
        ]

        // Method 1: If SecTaskCreateFromSelf is available
        if let createSelfPtr = secTaskCreateFromSelfPtr,
           let copyValuePtr = secTaskCopyValuePtr {

            typealias SecTaskCreateFromSelfFunc = @convention(c) (CFAllocator?) -> AnyObject?
            typealias SecTaskCopyValueFunc = @convention(c) (AnyObject, CFString, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<AnyObject>?

            let createSelf = unsafeBitCast(createSelfPtr, to: SecTaskCreateFromSelfFunc.self)
            let copyValue = unsafeBitCast(copyValuePtr, to: SecTaskCopyValueFunc.self)

            if let task = createSelf(nil) {
                for key in entitlementKeys {
                    var error: Unmanaged<CFError>?
                    let cfKey = key as CFString
                    let value = copyValue(task, cfKey, &error)

                    var result: [String: Any] = ["key": key]
                    if let val = value {
                        let obj = val.takeRetainedValue()
                        result["present"] = true
                        result["value"] = "\(obj)"
                        result["type"] = "\(type(of: obj))"
                    } else if let err = error {
                        let cfErr = err.takeRetainedValue()
                        result["present"] = false
                        result["error"] = CFErrorCopyDescription(cfErr) as String? ?? "unknown"
                    } else {
                        result["present"] = false
                        result["value"] = "nil"
                    }
                    engine.report(module: name, key: "entitlement_probe", value: result)
                }
            } else {
                engine.reportError(module: name, key: "SecTaskCreateFromSelf", error: "returned nil")
            }
        } else {
            engine.report(module: name, key: "entitlement_probe_method", value: "SecTask API unavailable, relying on csops blob only")
        }
    }

    // MARK: - Mobile Provision

    private func parseMobileProvision(engine: ReconEngine) {
        // Look for embedded.mobileprovision in the app bundle
        guard let bundlePath = Bundle.main.bundlePath as String? else {
            engine.reportError(module: name, key: "mobileprovision", error: "no bundle path")
            return
        }

        let provisionPath = (bundlePath as NSString).appendingPathComponent("embedded.mobileprovision")
        guard FileManager.default.fileExists(atPath: provisionPath) else {
            engine.report(module: name, key: "mobileprovision", value: [
                "exists": false,
                "path": provisionPath
            ] as [String: Any])
            return
        }

        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: provisionPath))
            engine.report(module: name, key: "mobileprovision_size", value: data.count)

            // mobileprovision is a CMS/PKCS#7 signed plist
            // The plist is between <?xml and </plist> tags within the binary
            if let str = String(data: data, encoding: .ascii) ?? String(data: data, encoding: .utf8) {
                // Find the XML plist within the CMS envelope
                if let xmlStart = str.range(of: "<?xml"),
                   let xmlEnd = str.range(of: "</plist>") {
                    let xmlStr = String(str[xmlStart.lowerBound...xmlEnd.upperBound])
                    if let xmlData = xmlStr.data(using: .utf8),
                       let plist = try PropertyListSerialization.propertyList(
                           from: xmlData, options: [], format: nil
                       ) as? [String: Any] {

                        // Extract key fields
                        if let teamID = plist["TeamIdentifier"] as? [String] {
                            engine.report(module: name, key: "provision_team_id", value: teamID)
                        }
                        if let appID = plist["application-identifier"] ?? (plist["Entitlements"] as? [String: Any])?["application-identifier"] {
                            engine.report(module: name, key: "provision_app_id", value: "\(appID)")
                        }
                        if let teamName = plist["TeamName"] as? String {
                            engine.report(module: name, key: "provision_team_name", value: teamName)
                        }
                        if let profileName = plist["Name"] as? String {
                            engine.report(module: name, key: "provision_profile_name", value: profileName)
                        }
                        if let uuid = plist["UUID"] as? String {
                            engine.report(module: name, key: "provision_uuid", value: uuid)
                        }
                        if let creation = plist["CreationDate"] as? Date {
                            engine.report(module: name, key: "provision_creation_date", value: "\(creation)")
                        }
                        if let expiration = plist["ExpirationDate"] as? Date {
                            engine.report(module: name, key: "provision_expiration_date", value: "\(expiration)")
                        }
                        if let devices = plist["ProvisionedDevices"] as? [String] {
                            engine.report(module: name, key: "provision_devices", value: [
                                "count": devices.count,
                                "devices": Array(devices.prefix(50))
                            ] as [String: Any])
                        }
                        if let entitlements = plist["Entitlements"] as? [String: Any] {
                            for (key, val) in entitlements {
                                engine.report(module: name, key: "provision_entitlement", value: [
                                    "key": key, "value": "\(val)"
                                ] as [String: Any])
                            }
                        }
                        if let platforms = plist["Platform"] as? [String] {
                            engine.report(module: name, key: "provision_platforms", value: platforms)
                        }
                        if let isXcode = plist["IsXcodeManaged"] as? Bool {
                            engine.report(module: name, key: "provision_xcode_managed", value: isXcode)
                        }
                        // ProvisionsAllDevices (enterprise)
                        if let allDevices = plist["ProvisionsAllDevices"] as? Bool {
                            engine.report(module: name, key: "provision_all_devices", value: allDevices)
                        }
                    }
                } else {
                    engine.reportError(module: name, key: "mobileprovision_xml", error: "could not find XML within CMS envelope")
                }
            }
        } catch {
            engine.reportError(module: name, key: "mobileprovision", error: error.localizedDescription)
        }
    }

    // MARK: - Code Signing Flags

    private func dumpCodeSigningFlags(engine: ReconEngine) {
        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        guard let csopsPtr = dlsym(handle, "csops") else {
            engine.reportError(module: name, key: "codesign_flags", error: "csops not found")
            return
        }
        let csops = unsafeBitCast(csopsPtr, to: CsopsFunc.self)

        var flags: UInt32 = 0
        errno = 0
        let ret = csops(getpid(), 0, &flags, MemoryLayout<UInt32>.size)

        guard ret == 0 else {
            engine.reportError(module: name, key: "codesign_flags", error: "csops failed: errno \(errno)")
            return
        }

        let flagDefs: [(String, UInt32)] = [
            ("CS_VALID", 0x00000001),
            ("CS_ADHOC", 0x00000002),
            ("CS_GET_TASK_ALLOW", 0x00000004),
            ("CS_INSTALLER", 0x00000008),
            ("CS_FORCED_LV", 0x00000010),
            ("CS_INVALID_ALLOWED", 0x00000020),
            ("CS_HARD", 0x00000100),
            ("CS_KILL", 0x00000200),
            ("CS_CHECK_EXPIRATION", 0x00000400),
            ("CS_RESTRICT", 0x00000800),
            ("CS_ENFORCEMENT", 0x00001000),
            ("CS_REQUIRE_LV", 0x00002000),
            ("CS_ENTITLEMENTS_VALIDATED", 0x00004000),
            ("CS_NVRAM_UNRESTRICTED", 0x00008000),
            ("CS_RUNTIME", 0x00010000),
            ("CS_LINKER_SIGNED", 0x00020000),
            ("CS_EXEC_SET_HARD", 0x00100000),
            ("CS_EXEC_SET_KILL", 0x00200000),
            ("CS_EXEC_SET_ENFORCEMENT", 0x00400000),
            ("CS_EXEC_INHERIT_SIP", 0x00800000),
            ("CS_KILLED", 0x01000000),
            ("CS_DYLD_PLATFORM", 0x02000000),
            ("CS_PLATFORM_BINARY", 0x04000000),
            ("CS_PLATFORM_PATH", 0x08000000),
            ("CS_DEBUGGED", 0x10000000),
            ("CS_SIGNED", 0x20000000),
            ("CS_DEV_CODE", 0x40000000)
        ]

        var flagResults: [String: Bool] = [:]
        var setFlags: [String] = []
        var unsetFlags: [String] = []

        for (flagName, flagBit) in flagDefs {
            let isSet = (flags & flagBit) != 0
            flagResults[flagName] = isSet
            if isSet { setFlags.append(flagName) }
            else { unsetFlags.append(flagName) }
        }

        engine.report(module: name, key: "codesign_flags", value: [
            "raw_flags": flags,
            "flags_hex": String(format: "0x%08x", flags),
            "flags": flagResults,
            "set_flags": setFlags,
            "unset_flags": unsetFlags
        ] as [String: Any])
    }
}
