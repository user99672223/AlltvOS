// KeychainProbeModule.swift
// TVOSRecon
//
// Probes the iOS/tvOS Keychain Services to discover what keychain items
// are accessible from a sandboxed sideloaded app. This reveals the app's
// keychain access groups, whether cross-app keychain sharing is possible,
// and what types of credentials or keys exist on the device. Security
// researchers should look for: unexpected access to other apps' items,
// system keychain groups that are readable, and whether Secure Enclave
// keys can be enumerated.

import Foundation
import Security

final class KeychainProbeModule: ReconModule {
    let name = "KeychainProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        enumerateKeychainClasses(engine: engine)
        testWriteAccess(engine: engine)
        probeAccessGroups(engine: engine)
    }

    private func enumerateKeychainClasses(engine: ReconEngine) {
        let classes: [(String, CFString)] = [
            ("GenericPassword", kSecClassGenericPassword),
            ("InternetPassword", kSecClassInternetPassword),
            ("Certificate", kSecClassCertificate),
            ("Key", kSecClassKey),
            ("Identity", kSecClassIdentity)
        ]

        for (className, secClass) in classes {
            let query: [String: Any] = [
                kSecClass as String: secClass,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecReturnAttributes as String: true,
                kSecReturnRef as String: false
            ]

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecSuccess, let items = result as? [[String: Any]] {
                engine.report(module: name, key: "class.\(className).count", value: items.count)
                for (idx, item) in items.enumerated() {
                    let prefix = "class.\(className).item[\(idx)]"
                    extractItemMetadata(engine: engine, prefix: prefix, item: item)
                }
            } else {
                engine.report(module: name, key: "class.\(className).status", value: secStatusString(status))
            }
        }
    }

    private func extractItemMetadata(engine: ReconEngine, prefix: String, item: [String: Any]) {
        let metadataKeys: [(String, CFString)] = [
            ("label", kSecAttrLabel),
            ("account", kSecAttrAccount),
            ("service", kSecAttrService),
            ("creationDate", kSecAttrCreationDate),
            ("modificationDate", kSecAttrModificationDate),
            ("accessGroup", kSecAttrAccessGroup),
            ("accessible", kSecAttrAccessible),
            ("synchronizable", kSecAttrSynchronizable),
            ("tokenID", kSecAttrTokenID),
            ("type", kSecAttrType),
            ("description", kSecAttrDescription),
            ("comment", kSecAttrComment),
            ("creator", kSecAttrCreator),
            ("issuer", kSecAttrIssuer),
            ("serialNumber", kSecAttrSerialNumber),
            ("subjectKeyID", kSecAttrSubjectKeyID),
            ("publicKeyHash", kSecAttrPublicKeyHash),
            ("keyClass", kSecAttrKeyClass),
            ("keyType", kSecAttrKeyType),
            ("keySizeInBits", kSecAttrKeySizeInBits),
            ("effectiveKeySize", kSecAttrEffectiveKeySize),
            ("isPermanent", kSecAttrIsPermanent),
            ("applicationTag", kSecAttrApplicationTag),
            ("canEncrypt", kSecAttrCanEncrypt),
            ("canDecrypt", kSecAttrCanDecrypt),
            ("canSign", kSecAttrCanSign),
            ("canVerify", kSecAttrCanVerify),
            ("canWrap", kSecAttrCanWrap),
            ("canUnwrap", kSecAttrCanUnwrap),
            ("canDerive", kSecAttrCanDerive),
        ]

        for (keyName, attrKey) in metadataKeys {
            if let value = item[attrKey as String] {
                if let dateVal = value as? Date {
                    engine.report(module: name, key: "\(prefix).\(keyName)", value: ISO8601DateFormatter().string(from: dateVal))
                } else if let dataVal = value as? Data {
                    engine.report(module: name, key: "\(prefix).\(keyName)", value: dataVal.base64EncodedString())
                } else {
                    engine.report(module: name, key: "\(prefix).\(keyName)", value: "\(value)")
                }
            }
        }

        if let tokenID = item[kSecAttrTokenID as String] as? String {
            let isSecureEnclave = tokenID == (kSecAttrTokenIDSecureEnclave as String)
            engine.report(module: name, key: "\(prefix).isSecureEnclaveKey", value: isSecureEnclave)
        }
    }

    private func testWriteAccess(engine: ReconEngine) {
        let testTag = "com.tvosrecon.test.\(UUID().uuidString)"

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: testTag,
            kSecAttrAccount as String: "recon_test",
            kSecValueData as String: "test_value".data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        engine.report(module: name, key: "writeAccess.add", value: secStatusString(addStatus))

        if addStatus == errSecSuccess {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: testTag,
                kSecAttrAccount as String: "recon_test"
            ]
            let delStatus = SecItemDelete(deleteQuery as CFDictionary)
            engine.report(module: name, key: "writeAccess.delete", value: secStatusString(delStatus))
        }

        let accessibilityValues: [(String, CFString)] = [
            ("WhenUnlocked", kSecAttrAccessibleWhenUnlocked),
            ("AfterFirstUnlock", kSecAttrAccessibleAfterFirstUnlock),
            ("WhenUnlockedThisDeviceOnly", kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
            ("AfterFirstUnlockThisDeviceOnly", kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ("WhenPasscodeSetThisDeviceOnly", kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
        ]

        for (accName, accValue) in accessibilityValues {
            let tag = "com.tvosrecon.acctest.\(accName).\(UUID().uuidString)"
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: tag,
                kSecAttrAccount as String: "acc_test",
                kSecValueData as String: "t".data(using: .utf8)!,
                kSecAttrAccessible as String: accValue
            ]
            let st = SecItemAdd(q as CFDictionary, nil)
            engine.report(module: name, key: "writeAccess.accessibility.\(accName)", value: secStatusString(st))
            if st == errSecSuccess {
                SecItemDelete([
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: tag,
                    kSecAttrAccount as String: "acc_test"
                ] as CFDictionary)
            }
        }
    }

    private func probeAccessGroups(engine: ReconEngine) {
        let groups = ["*", "apple", "com.apple.token", "com.apple.security.sos",
                      "com.apple.sbd", "com.apple.swcd", "com.apple.lakitu",
                      "com.apple.GeoServices", "com.apple.accounts",
                      "com.apple.preferences", "com.apple.cfnetwork"]

        if let teamID = Bundle.main.infoDictionary?["AppIdentifierPrefix"] as? String {
            engine.report(module: name, key: "teamIdentifier", value: teamID)
        }
        if let appID = Bundle.main.bundleIdentifier {
            engine.report(module: name, key: "bundleIdentifier", value: appID)
        }

        for group in groups {
            for (className, secClass) in [("GenericPassword", kSecClassGenericPassword),
                                           ("Key", kSecClassKey),
                                           ("Certificate", kSecClassCertificate)] as [(String, CFString)] {
                let query: [String: Any] = [
                    kSecClass as String: secClass,
                    kSecAttrAccessGroup as String: group,
                    kSecMatchLimit as String: kSecMatchLimitAll,
                    kSecReturnAttributes as String: true
                ]

                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)

                if status == errSecSuccess, let items = result as? [[String: Any]] {
                    engine.report(module: name, key: "accessGroup.\(group).\(className).count", value: items.count)
                    for (idx, item) in items.prefix(20).enumerated() {
                        let prefix = "accessGroup.\(group).\(className).item[\(idx)]"
                        if let label = item[kSecAttrLabel as String] {
                            engine.report(module: name, key: "\(prefix).label", value: "\(label)")
                        }
                        if let account = item[kSecAttrAccount as String] {
                            engine.report(module: name, key: "\(prefix).account", value: "\(account)")
                        }
                        if let service = item[kSecAttrService as String] {
                            engine.report(module: name, key: "\(prefix).service", value: "\(service)")
                        }
                    }
                } else {
                    engine.report(module: name, key: "accessGroup.\(group).\(className).status", value: secStatusString(status))
                }
            }
        }

        let seQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        var seResult: AnyObject?
        let seStatus = SecItemCopyMatching(seQuery as CFDictionary, &seResult)
        if seStatus == errSecSuccess, let items = seResult as? [[String: Any]] {
            engine.report(module: name, key: "secureEnclave.keyCount", value: items.count)
            for (idx, item) in items.prefix(50).enumerated() {
                if let label = item[kSecAttrLabel as String] {
                    engine.report(module: name, key: "secureEnclave.key[\(idx)].label", value: "\(label)")
                }
                if let keyType = item[kSecAttrKeyType as String] {
                    engine.report(module: name, key: "secureEnclave.key[\(idx)].keyType", value: "\(keyType)")
                }
                if let bits = item[kSecAttrKeySizeInBits as String] {
                    engine.report(module: name, key: "secureEnclave.key[\(idx)].keySizeInBits", value: "\(bits)")
                }
            }
        } else {
            engine.report(module: name, key: "secureEnclave.status", value: secStatusString(seStatus))
        }
    }

    private func secStatusString(_ status: OSStatus) -> String {
        let knownCodes: [OSStatus: String] = [
            errSecSuccess: "errSecSuccess (0)",
            errSecItemNotFound: "errSecItemNotFound (-25300)",
            errSecAuthFailed: "errSecAuthFailed (-25293)",
            errSecDuplicateItem: "errSecDuplicateItem (-25299)",
            errSecInteractionNotAllowed: "errSecInteractionNotAllowed (-25308)",
            errSecDecode: "errSecDecode (-26275)",
            errSecParam: "errSecParam (-50)",
            errSecAllocate: "errSecAllocate (-108)",
            errSecNotAvailable: "errSecNotAvailable (-25291)",
            errSecUnimplemented: "errSecUnimplemented (-4)",
            errSecMissingEntitlement: "errSecMissingEntitlement (-34018)",
            errSecIO: "errSecIO (-36)",
        ]
        return knownCodes[status] ?? "OSStatus(\(status))"
    }
}
