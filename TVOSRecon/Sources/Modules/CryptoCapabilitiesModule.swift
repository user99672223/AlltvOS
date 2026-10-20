// CryptoCapabilitiesModule.swift
// Probes cryptographic capabilities: SecKey algorithms, Secure Enclave, hash functions,
// trust anchors, and CryptoKit availability. Reveals what crypto primitives the sandbox allows.

import Foundation
import Security
import CommonCrypto
#if canImport(CryptoKit)
import CryptoKit
#endif

final class CryptoCapabilitiesModule: ReconModule {
    let name = "CryptoCapabilities"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        testSecKeyAlgorithms(engine: engine)
        testSecureEnclaveKeyGen(engine: engine)
        testHashFunctions(engine: engine)
        testTrustAnchors(engine: engine)
        testCryptoKit(engine: engine)
    }

    // MARK: - SecKey Algorithm Support

    private func testSecKeyAlgorithms(engine: ReconEngine) {
        let rsaKeyParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]
        var error: Unmanaged<CFError>?
        guard let rsaPrivKey = SecKeyCreateRandomKey(rsaKeyParams as CFDictionary, &error) else {
            engine.reportError(module: name, key: "rsa_key_gen", error: "Failed: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return
        }
        guard let rsaPubKey = SecKeyCopyPublicKey(rsaPrivKey) else {
            engine.reportError(module: name, key: "rsa_pubkey", error: "Failed to extract public key")
            return
        }

        let ecKeyParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256
        ]
        let ecPrivKey = SecKeyCreateRandomKey(ecKeyParams as CFDictionary, &error)
        let ecPubKey = ecPrivKey.flatMap { SecKeyCopyPublicKey($0) }

        let signAlgorithms: [(String, SecKeyAlgorithm)] = [
            ("rsaSignatureRaw", .rsaSignatureRaw),
            ("rsaSignatureDigestPKCS1v15SHA1", .rsaSignatureDigestPKCS1v15SHA1),
            ("rsaSignatureDigestPKCS1v15SHA256", .rsaSignatureDigestPKCS1v15SHA256),
            ("rsaSignatureDigestPKCS1v15SHA384", .rsaSignatureDigestPKCS1v15SHA384),
            ("rsaSignatureDigestPKCS1v15SHA512", .rsaSignatureDigestPKCS1v15SHA512),
            ("rsaSignatureMessagePKCS1v15SHA1", .rsaSignatureMessagePKCS1v15SHA1),
            ("rsaSignatureMessagePKCS1v15SHA256", .rsaSignatureMessagePKCS1v15SHA256),
            ("rsaSignatureMessagePKCS1v15SHA384", .rsaSignatureMessagePKCS1v15SHA384),
            ("rsaSignatureMessagePKCS1v15SHA512", .rsaSignatureMessagePKCS1v15SHA512),
            ("rsaSignatureDigestPSSSHA1", .rsaSignatureDigestPSSSHA1),
            ("rsaSignatureDigestPSSSHA256", .rsaSignatureDigestPSSSHA256),
            ("rsaSignatureDigestPSSSHA384", .rsaSignatureDigestPSSSHA384),
            ("rsaSignatureDigestPSSSHA512", .rsaSignatureDigestPSSSHA512),
        ]

        for (aName, alg) in signAlgorithms {
            let canSign = SecKeyIsAlgorithmSupported(rsaPrivKey, .sign, alg)
            let canVerify = SecKeyIsAlgorithmSupported(rsaPubKey, .verify, alg)
            engine.report(module: name, key: "rsa_sign_\(aName)", value: canSign)
            engine.report(module: name, key: "rsa_verify_\(aName)", value: canVerify)
        }

        let encryptAlgorithms: [(String, SecKeyAlgorithm)] = [
            ("rsaEncryptionRaw", .rsaEncryptionRaw),
            ("rsaEncryptionPKCS1", .rsaEncryptionPKCS1),
            ("rsaEncryptionOAEPSHA1", .rsaEncryptionOAEPSHA1),
            ("rsaEncryptionOAEPSHA256", .rsaEncryptionOAEPSHA256),
            ("rsaEncryptionOAEPSHA384", .rsaEncryptionOAEPSHA384),
            ("rsaEncryptionOAEPSHA512", .rsaEncryptionOAEPSHA512),
        ]

        for (aName, alg) in encryptAlgorithms {
            let canEnc = SecKeyIsAlgorithmSupported(rsaPubKey, .encrypt, alg)
            let canDec = SecKeyIsAlgorithmSupported(rsaPrivKey, .decrypt, alg)
            engine.report(module: name, key: "rsa_encrypt_\(aName)", value: canEnc)
            engine.report(module: name, key: "rsa_decrypt_\(aName)", value: canDec)
        }

        if let ecPriv = ecPrivKey, let ecPub = ecPubKey {
            let ecdsaAlgorithms: [(String, SecKeyAlgorithm)] = [
                ("ecdsaSignatureDigestX962SHA1", .ecdsaSignatureDigestX962SHA1),
                ("ecdsaSignatureDigestX962SHA256", .ecdsaSignatureDigestX962SHA256),
                ("ecdsaSignatureDigestX962SHA384", .ecdsaSignatureDigestX962SHA384),
                ("ecdsaSignatureDigestX962SHA512", .ecdsaSignatureDigestX962SHA512),
                ("ecdsaSignatureMessageX962SHA1", .ecdsaSignatureMessageX962SHA1),
                ("ecdsaSignatureMessageX962SHA256", .ecdsaSignatureMessageX962SHA256),
                ("ecdsaSignatureMessageX962SHA384", .ecdsaSignatureMessageX962SHA384),
                ("ecdsaSignatureMessageX962SHA512", .ecdsaSignatureMessageX962SHA512),
            ]
            for (aName, alg) in ecdsaAlgorithms {
                let canSign = SecKeyIsAlgorithmSupported(ecPriv, .sign, alg)
                let canVerify = SecKeyIsAlgorithmSupported(ecPub, .verify, alg)
                engine.report(module: name, key: "ec_sign_\(aName)", value: canSign)
                engine.report(module: name, key: "ec_verify_\(aName)", value: canVerify)
            }

            let ecdhAlgorithms: [(String, SecKeyAlgorithm)] = [
                ("ecdhKeyExchangeStandard", .ecdhKeyExchangeStandard),
                ("ecdhKeyExchangeCofactor", .ecdhKeyExchangeCofactor),
                ("ecdhKeyExchangeStandardX963SHA1", .ecdhKeyExchangeStandardX963SHA1),
                ("ecdhKeyExchangeStandardX963SHA256", .ecdhKeyExchangeStandardX963SHA256),
                ("ecdhKeyExchangeStandardX963SHA384", .ecdhKeyExchangeStandardX963SHA384),
                ("ecdhKeyExchangeStandardX963SHA512", .ecdhKeyExchangeStandardX963SHA512),
            ]
            for (aName, alg) in ecdhAlgorithms {
                let supported = SecKeyIsAlgorithmSupported(ecPriv, .keyExchange, alg)
                engine.report(module: name, key: "ecdh_\(aName)", value: supported)
            }
        } else {
            engine.reportError(module: name, key: "ec_key_gen", error: "Failed to generate EC key")
        }
    }

    // MARK: - Secure Enclave

    private func testSecureEnclaveKeyGen(engine: ReconEngine) {
        let keySizes: [(String, Int)] = [("P256", 256), ("P384", 384), ("P521", 521)]
        for (label, bits) in keySizes {
            var error: Unmanaged<CFError>?
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .privateKeyUsage,
                &error
            )
            if access == nil {
                engine.reportError(module: name, key: "se_access_control_\(label)", error: error?.takeRetainedValue().localizedDescription ?? "unknown")
                continue
            }
            let params: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: bits,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: false,
                    kSecAttrAccessControl as String: access!
                ] as [String: Any]
            ]
            var genError: Unmanaged<CFError>?
            let key = SecKeyCreateRandomKey(params as CFDictionary, &genError)
            if let _ = key {
                engine.report(module: name, key: "secure_enclave_\(label)", value: "success")
            } else {
                engine.report(module: name, key: "secure_enclave_\(label)", value: "failed: \(genError?.takeRetainedValue().localizedDescription ?? "unknown")")
            }
        }
    }

    // MARK: - Hash Functions

    private func testHashFunctions(engine: ReconEngine) {
        let dataSize = 1024 * 1024
        let data = Data(count: dataSize)
        let bytes = [UInt8](data)

        // MD5
        do {
            var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            let start = CFAbsoluteTimeGetCurrent()
            CC_MD5(bytes, CC_LONG(bytes.count), &digest)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            engine.report(module: name, key: "hash_CC_MD5_1MB_seconds", value: elapsed)
            engine.report(module: name, key: "hash_CC_MD5_available", value: true)
        }

        // SHA1
        do {
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            let start = CFAbsoluteTimeGetCurrent()
            CC_SHA1(bytes, CC_LONG(bytes.count), &digest)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            engine.report(module: name, key: "hash_CC_SHA1_1MB_seconds", value: elapsed)
            engine.report(module: name, key: "hash_CC_SHA1_available", value: true)
        }

        // SHA256
        do {
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            let start = CFAbsoluteTimeGetCurrent()
            CC_SHA256(bytes, CC_LONG(bytes.count), &digest)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            engine.report(module: name, key: "hash_CC_SHA256_1MB_seconds", value: elapsed)
            engine.report(module: name, key: "hash_CC_SHA256_available", value: true)
        }

        // SHA384
        do {
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            let start = CFAbsoluteTimeGetCurrent()
            CC_SHA384(bytes, CC_LONG(bytes.count), &digest)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            engine.report(module: name, key: "hash_CC_SHA384_1MB_seconds", value: elapsed)
            engine.report(module: name, key: "hash_CC_SHA384_available", value: true)
        }

        // SHA512
        do {
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            let start = CFAbsoluteTimeGetCurrent()
            CC_SHA512(bytes, CC_LONG(bytes.count), &digest)
            let elapsed = CFAbsoluteTimeGetCurrent() - start
            engine.report(module: name, key: "hash_CC_SHA512_1MB_seconds", value: elapsed)
            engine.report(module: name, key: "hash_CC_SHA512_available", value: true)
        }
    }

    // MARK: - Trust Anchors

    private func testTrustAnchors(engine: ReconEngine) {
        var anchors: CFArray?
        let status = SecTrustCopyAnchorCertificates(&anchors)
        if status == errSecSuccess, let certs = anchors as? [SecCertificate] {
            engine.report(module: name, key: "trust_anchor_count", value: certs.count)
            for (i, cert) in certs.prefix(10).enumerated() {
                if let summary = SecCertificateCopySubjectSummary(cert) as String? {
                    engine.report(module: name, key: "trust_anchor_\(i)_subject", value: summary)
                }
            }
        } else {
            engine.reportError(module: name, key: "trust_anchors", error: "SecTrustCopyAnchorCertificates failed: \(status)")
        }

        // Basic trust evaluation test
        do {
            let policy = SecPolicyCreateBasicX509()
            engine.report(module: name, key: "sec_policy_basic_x509", value: "created")
            let sslPolicy = SecPolicyCreateSSL(true, "apple.com" as CFString)
            engine.report(module: name, key: "sec_policy_ssl", value: "created")
            _ = sslPolicy
            _ = policy
        }
    }

    // MARK: - CryptoKit

    private func testCryptoKit(engine: ReconEngine) {
        #if canImport(CryptoKit)
        if #available(tvOS 13.0, *) {
            // P256
            do {
                let key = P256.KeyAgreement.PrivateKey()
                engine.report(module: name, key: "cryptokit_p256_keygen", value: "success (pubkey: \(key.publicKey.rawRepresentation.count) bytes)")
            }

            // P384
            do {
                let key = P384.KeyAgreement.PrivateKey()
                engine.report(module: name, key: "cryptokit_p384_keygen", value: "success (pubkey: \(key.publicKey.rawRepresentation.count) bytes)")
            }

            // P521
            do {
                let key = P521.KeyAgreement.PrivateKey()
                engine.report(module: name, key: "cryptokit_p521_keygen", value: "success (pubkey: \(key.publicKey.rawRepresentation.count) bytes)")
            }

            // Curve25519
            do {
                let key = Curve25519.KeyAgreement.PrivateKey()
                engine.report(module: name, key: "cryptokit_curve25519_keygen", value: "success (pubkey: \(key.publicKey.rawRepresentation.count) bytes)")
            }

            // SymmetricKey
            do {
                let symKey = SymmetricKey(size: .bits256)
                engine.report(module: name, key: "cryptokit_symmetric_key_256", value: "success (data: \(symKey.bitCount) bits)")
            }

            // AES-GCM self-test
            do {
                let key = SymmetricKey(size: .bits256)
                let plaintext = Data("TVOSRecon CryptoKit self-test".utf8)
                let sealed = try AES.GCM.seal(plaintext, using: key)
                let opened = try AES.GCM.open(sealed, using: key)
                let matches = opened == plaintext
                engine.report(module: name, key: "cryptokit_aesgcm_selftest", value: matches ? "pass" : "FAIL: decrypted != plaintext")
            } catch {
                engine.reportError(module: name, key: "cryptokit_aesgcm_selftest", error: error.localizedDescription)
            }

            // ChaChaPoly self-test
            do {
                let key = SymmetricKey(size: .bits256)
                let plaintext = Data("TVOSRecon ChaChaPoly self-test".utf8)
                let sealed = try ChaChaPoly.seal(plaintext, using: key)
                let opened = try ChaChaPoly.open(sealed, using: key)
                let matches = opened == plaintext
                engine.report(module: name, key: "cryptokit_chacha_selftest", value: matches ? "pass" : "FAIL: decrypted != plaintext")
            } catch {
                engine.reportError(module: name, key: "cryptokit_chacha_selftest", error: error.localizedDescription)
            }

            // HMAC
            do {
                let key = SymmetricKey(size: .bits256)
                let data = Data("test".utf8)
                let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
                engine.report(module: name, key: "cryptokit_hmac_sha256", value: "success (\(mac.description.prefix(32))...)")
            }

            // HKDF
            if #available(tvOS 14.0, *) {
                do {
                    let inputKey = SymmetricKey(size: .bits256)
                    let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: inputKey, outputByteCount: 32)
                    engine.report(module: name, key: "cryptokit_hkdf_sha256", value: "success (\(derived.bitCount) bits)")
                }
            }
        } else {
            engine.report(module: name, key: "cryptokit_available", value: false)
        }
        #else
        engine.report(module: name, key: "cryptokit_available", value: false)
        #endif
    }
}
