// PasteboardAndAppStateModule.swift
// Probes pasteboard contents, application state, bundle information, UserDefaults,
// and file system directories. Reveals what data and configuration is accessible
// to a sandboxed sideloaded app.

import Foundation
import UIKit

final class PasteboardAndAppStateModule: ReconModule {
    let name = "PasteboardAndAppState"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probePasteboard(engine: engine)
        probeAppState(engine: engine)
        probeBundleInfo(engine: engine)
        probeUserDefaults(engine: engine)
        probeCloudAndUbiquity(engine: engine)
        probeFileManagerDirs(engine: engine)
    }

    // MARK: - Pasteboard

    private func probePasteboard(engine: ReconEngine) {
        // UIPasteboard is unavailable on tvOS, so the whole probe is compiled out there.
        #if !os(tvOS)
        DispatchQueue.main.sync {
            let pb = UIPasteboard.general
            engine.report(module: name, key: "pasteboard_name", value: pb.name.rawValue)
            engine.report(module: name, key: "pasteboard_changeCount", value: pb.changeCount)
            engine.report(module: name, key: "pasteboard_numberOfItems", value: pb.numberOfItems)
            engine.report(module: name, key: "pasteboard_hasStrings", value: pb.hasStrings)
            engine.report(module: name, key: "pasteboard_hasImages", value: pb.hasImages)
            engine.report(module: name, key: "pasteboard_hasURLs", value: pb.hasURLs)
            engine.report(module: name, key: "pasteboard_hasColors", value: pb.hasColors)

            let types = pb.types
            engine.report(module: name, key: "pasteboard_types", value: types)

            // Find pasteboard
            if let findPb = UIPasteboard(name: .find, create: false) {
                engine.report(module: name, key: "pasteboard_find_exists", value: true)
                engine.report(module: name, key: "pasteboard_find_changeCount", value: findPb.changeCount)
                engine.report(module: name, key: "pasteboard_find_numberOfItems", value: findPb.numberOfItems)
            } else {
                engine.report(module: name, key: "pasteboard_find_exists", value: false)
            }
        }
        #else
        engine.report(module: name, key: "pasteboard_status", value: "UIPasteboard_unavailable_on_tvOS")
        #endif
    }

    // MARK: - App State

    private func probeAppState(engine: ReconEngine) {
        DispatchQueue.main.sync {
            let app = UIApplication.shared

            let stateStr: String
            switch app.applicationState {
            case .active: stateStr = "active"
            case .inactive: stateStr = "inactive"
            case .background: stateStr = "background"
            @unknown default: stateStr = "unknown(\(app.applicationState.rawValue))"
            }
            engine.report(module: name, key: "app_state", value: stateStr)
            engine.report(module: name, key: "app_backgroundTimeRemaining", value: app.backgroundTimeRemaining)
            engine.report(module: name, key: "app_isProtectedDataAvailable", value: app.isProtectedDataAvailable)
            engine.report(module: name, key: "app_preferredContentSizeCategory", value: app.preferredContentSizeCategory.rawValue)
            engine.report(module: name, key: "app_isIdleTimerDisabled", value: app.isIdleTimerDisabled)
            engine.report(module: name, key: "app_userInterfaceLayoutDirection", value: app.userInterfaceLayoutDirection.rawValue)

            if #available(tvOS 13.0, *) {
                for scene in app.connectedScenes {
                    engine.report(module: name, key: "scene_\(scene.session.persistentIdentifier)_role", value: scene.session.role.rawValue)
                    engine.report(module: name, key: "scene_\(scene.session.persistentIdentifier)_state", value: "\(scene.activationState.rawValue)")
                }
            }
        }
    }

    // MARK: - Bundle Info

    private func probeBundleInfo(engine: ReconEngine) {
        let bundle = Bundle.main

        // Full info dictionary
        if let info = bundle.infoDictionary {
            for (key, value) in info {
                engine.report(module: name, key: "bundle_info_\(key)", value: "\(value)")
            }
        }

        engine.report(module: name, key: "bundle_executablePath", value: bundle.executablePath ?? "nil")
        engine.report(module: name, key: "bundle_resourcePath", value: bundle.resourcePath ?? "nil")
        engine.report(module: name, key: "bundle_privateFrameworksPath", value: bundle.privateFrameworksPath ?? "nil")
        engine.report(module: name, key: "bundle_sharedFrameworksPath", value: bundle.sharedFrameworksPath ?? "nil")
        engine.report(module: name, key: "bundle_sharedSupportPath", value: bundle.sharedSupportPath ?? "nil")
        engine.report(module: name, key: "bundle_builtInPlugInsPath", value: bundle.builtInPlugInsPath ?? "nil")
        engine.report(module: name, key: "bundle_appStoreReceiptURL", value: bundle.appStoreReceiptURL?.absoluteString ?? "nil")
        engine.report(module: name, key: "bundle_bundleIdentifier", value: bundle.bundleIdentifier ?? "nil")
        engine.report(module: name, key: "bundle_bundlePath", value: bundle.bundlePath)

        // All frameworks
        let frameworks = Bundle.allFrameworks
        engine.report(module: name, key: "allFrameworks_count", value: frameworks.count)
        for (i, fw) in frameworks.enumerated() {
            let fwName = fw.bundleURL.lastPathComponent
            engine.report(module: name, key: "framework_\(i)", value: [
                "name": fwName,
                "path": fw.bundlePath,
                "loaded": fw.isLoaded,
                "identifier": fw.bundleIdentifier ?? "nil"
            ] as [String: Any])
        }

        // All bundles
        let bundles = Bundle.allBundles
        engine.report(module: name, key: "allBundles_count", value: bundles.count)
        for (i, b) in bundles.enumerated() {
            engine.report(module: name, key: "bundle_\(i)", value: [
                "path": b.bundlePath,
                "loaded": b.isLoaded,
                "identifier": b.bundleIdentifier ?? "nil"
            ] as [String: Any])
        }
    }

    // MARK: - UserDefaults

    private func probeUserDefaults(engine: ReconEngine) {
        // Standard defaults
        let standardDict = UserDefaults.standard.dictionaryRepresentation()
        engine.report(module: name, key: "userdefaults_standard_count", value: standardDict.count)
        for (key, value) in standardDict {
            let strValue: String
            if let data = value as? Data {
                strValue = "Data(\(data.count) bytes)"
            } else {
                strValue = "\(value)"
            }
            engine.report(module: name, key: "userdefaults_standard_\(key)", value: strValue.prefix(1024).description)
        }

        // Apple suite defaults
        let suites = [
            "com.apple.springboard",
            "com.apple.UIKit",
            "com.apple.coremedia",
            "com.apple.Preferences",
            "com.apple.TVSettings",
        ]
        for suite in suites {
            if let defaults = UserDefaults(suiteName: suite) {
                let dict = defaults.dictionaryRepresentation()
                let ownKeys = dict.keys.filter { !standardDict.keys.contains($0) }
                engine.report(module: name, key: "userdefaults_\(suite)_total_keys", value: dict.count)
                engine.report(module: name, key: "userdefaults_\(suite)_unique_keys", value: ownKeys.count)
                for key in ownKeys.prefix(50) {
                    if let val = dict[key] {
                        engine.report(module: name, key: "userdefaults_\(suite)_\(key)", value: "\(val)".prefix(512).description)
                    }
                }
            } else {
                engine.reportError(module: name, key: "userdefaults_\(suite)", error: "failed to create")
            }
        }
    }

    // MARK: - iCloud / Ubiquity

    private func probeCloudAndUbiquity(engine: ReconEngine) {
        let fm = FileManager.default
        let token = fm.ubiquityIdentityToken
        engine.report(module: name, key: "ubiquityIdentityToken", value: token != nil ? "present" : "nil")

        let kvStore = NSUbiquitousKeyValueStore.default
        let kvDict = kvStore.dictionaryRepresentation
        engine.report(module: name, key: "icloud_kvs_key_count", value: kvDict.count)
        for (key, value) in kvDict {
            engine.report(module: name, key: "icloud_kvs_\(key)", value: "\(value)".prefix(512).description)
        }
    }

    // MARK: - FileManager Directories

    private func probeFileManagerDirs(engine: ReconEngine) {
        let fm = FileManager.default

        engine.report(module: name, key: "fm_temporaryDirectory", value: fm.temporaryDirectory.path)
        engine.report(module: name, key: "fm_homeDirectory", value: NSHomeDirectory())
        engine.report(module: name, key: "fm_currentDirectoryPath", value: fm.currentDirectoryPath)

        let directories: [(String, FileManager.SearchPathDirectory)] = [
            ("applicationDirectory", .applicationDirectory),
            ("libraryDirectory", .libraryDirectory),
            ("cachesDirectory", .cachesDirectory),
            ("documentDirectory", .documentDirectory),
            ("applicationSupportDirectory", .applicationSupportDirectory),
            ("downloadsDirectory", .downloadsDirectory),
            ("moviesDirectory", .moviesDirectory),
            ("musicDirectory", .musicDirectory),
            ("picturesDirectory", .picturesDirectory),
            ("sharedPublicDirectory", .sharedPublicDirectory),
            ("autosavedInformationDirectory", .autosavedInformationDirectory),
            ("preferencePanesDirectory", .preferencePanesDirectory),
            ("itemReplacementDirectory", .itemReplacementDirectory),
        ]

        let domainMasks: [(String, FileManager.SearchPathDomainMask)] = [
            ("user", .userDomainMask),
            ("local", .localDomainMask),
            ("network", .networkDomainMask),
            ("system", .systemDomainMask),
        ]

        for (dirName, dir) in directories {
            for (domainName, domain) in domainMasks {
                let paths = NSSearchPathForDirectoriesInDomains(dir, domain, true)
                if !paths.isEmpty {
                    engine.report(module: name, key: "search_path_\(dirName)_\(domainName)", value: paths)
                }
            }
        }

        // confstr-based directories
        let confstrs: [(String, Int32)] = [
            ("_CS_DARWIN_USER_DIR", _CS_DARWIN_USER_DIR),
            ("_CS_DARWIN_USER_TEMP_DIR", _CS_DARWIN_USER_TEMP_DIR),
            ("_CS_DARWIN_USER_CACHE_DIR", _CS_DARWIN_USER_CACHE_DIR),
            ("_CS_PATH", _CS_PATH),
        ]
        for (label, key) in confstrs {
            let bufLen = confstr(key, nil, 0)
            if bufLen > 0 {
                var buf = [CChar](repeating: 0, count: bufLen)
                confstr(key, &buf, bufLen)
                engine.report(module: name, key: "confstr_\(label)", value: String(cString: buf))
            } else {
                engine.reportError(module: name, key: "confstr_\(label)", error: "returned 0")
            }
        }
    }
}
