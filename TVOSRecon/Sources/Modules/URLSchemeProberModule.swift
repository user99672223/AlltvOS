// URLSchemeProberModule.swift
// TVOSRecon - Module 22: URL Scheme Prober
//
// Tests which URL schemes are registered on the device via canOpenURL.
// Each available scheme reveals an installed app or system capability.
// Also probes for LSApplicationWorkspace to enumerate installed bundles
// directly. This maps the software surface area of the device.

import Foundation
import UIKit

final class URLSchemeProberModule: ReconModule {
    let name = "URLSchemeProber"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeURLSchemes(engine: engine)
        probeLSApplicationWorkspace(engine: engine)
        probeOpenURLCapabilities(engine: engine)
    }

    // MARK: - URL Schemes

    private func probeURLSchemes(engine: ReconEngine) {
        let schemes = [
            // Communication
            "tel", "mailto", "sms", "facetime", "facetime-audio",
            // Apple apps
            "maps", "music", "videos", "photos", "camera",
            // Settings
            "settings", "app-settings", "prefs", "App-prefs",
            // Game Center & Store
            "gamecenter", "itms", "itms-apps", "itms-appss", "itms-services",
            // tvOS specific
            "x-apple-surfboard", "com.apple.tv", "com.apple.TVAirPlay",
            "com.apple.TVSettings", "com.apple.TVRemote",
            // Apple internal
            "x-apple-pbb", "mobilesafari", "safari",
            "x-apple-ck-container-environment",
            // Shortcuts / Workflow
            "shortcuts", "workflow",
            // Jailbreak related
            "cydia", "sileo", "zebra",
            // Protocols
            "ssh", "ftp", "vnc", "smb", "nfs",
            // Social media
            "fb", "twitter", "instagram", "youtube", "tiktok", "snapchat",
            // Streaming
            "netflix", "plex", "vlc", "infuse", "kodi",
            "hulu", "disneyplus", "amazonprime", "hbomax",
            // Utilities
            "x-callback-url", "db-auth", "dbapi-1",
            // Additional Apple
            "calshow", "x-apple-calevent", "message",
            "ibooks", "podcasts", "shazam",
            "x-web-search", "x-apple-reminder",
            "findmy", "files", "measure",
            // Fitness / Health
            "x-apple-health",
            // Developer
            "xcdevice", "xcode",
            // Miscellaneous
            "comgooglemaps", "waze", "uber", "lyft",
            "whatsapp", "telegram", "signal", "discord",
            "slack", "zoom", "teams",
            "spotify", "deezer", "tidal",
            "twitch", "steam"
        ]

        var availableCount = 0
        var unavailableCount = 0

        for scheme in schemes {
            guard let url = URL(string: "\(scheme)://test") else {
                engine.reportError(module: name, key: "scheme.\(scheme)", error: "invalid_url")
                continue
            }

            // canOpenURL must be called on main thread
            var canOpen = false
            if Thread.isMainThread {
                canOpen = UIApplication.shared.canOpenURL(url)
            } else {
                let semaphore = DispatchSemaphore(value: 0)
                DispatchQueue.main.async {
                    canOpen = UIApplication.shared.canOpenURL(url)
                    semaphore.signal()
                }
                semaphore.wait()
            }

            engine.report(module: name, key: "scheme.\(scheme)", value: canOpen ? "available" : "unavailable")
            if canOpen {
                availableCount += 1
            } else {
                unavailableCount += 1
            }
        }

        engine.report(module: name, key: "scheme_summary", value: [
            "total_tested": schemes.count,
            "available": availableCount,
            "unavailable": unavailableCount
        ])
    }

    // MARK: - LSApplicationWorkspace

    private func probeLSApplicationWorkspace(engine: ReconEngine) {
        guard let lsClass = NSClassFromString("LSApplicationWorkspace") else {
            engine.report(module: name, key: "LSApplicationWorkspace", value: "class_not_found")
            return
        }

        engine.report(module: name, key: "LSApplicationWorkspace", value: "class_exists")

        // Try to get default workspace
        let defaultSel = NSSelectorFromString("defaultWorkspace")
        guard lsClass.responds(to: defaultSel) else {
            engine.report(module: name, key: "LSApplicationWorkspace.defaultWorkspace", value: "selector_not_found")
            return
        }

        guard let workspace = (lsClass as AnyObject).perform(defaultSel)?.takeUnretainedValue() else {
            engine.report(module: name, key: "LSApplicationWorkspace.defaultWorkspace", value: "returned_nil")
            return
        }

        engine.report(module: name, key: "LSApplicationWorkspace.defaultWorkspace", value: "obtained")

        // Try allApplications
        let allAppsSel = NSSelectorFromString("allApplications")
        if (workspace as AnyObject).responds(to: allAppsSel) {
            if let apps = (workspace as AnyObject).perform(allAppsSel)?.takeUnretainedValue() as? [AnyObject] {
                engine.report(module: name, key: "installed_apps_count", value: apps.count)

                for (idx, app) in apps.enumerated() {
                    var appInfo: [String: Any] = [:]

                    // applicationIdentifier
                    let bundleIdSel = NSSelectorFromString("applicationIdentifier")
                    if app.responds(to: bundleIdSel),
                       let bundleId = app.perform(bundleIdSel)?.takeUnretainedValue() as? String {
                        appInfo["bundleId"] = bundleId
                    }

                    // localizedName
                    let nameSel = NSSelectorFromString("localizedName")
                    if app.responds(to: nameSel),
                       let appName = app.perform(nameSel)?.takeUnretainedValue() as? String {
                        appInfo["name"] = appName
                    }

                    // applicationType
                    let typeSel = NSSelectorFromString("applicationType")
                    if app.responds(to: typeSel),
                       let appType = app.perform(typeSel)?.takeUnretainedValue() as? String {
                        appInfo["type"] = appType
                    }

                    // bundleVersion
                    let verSel = NSSelectorFromString("bundleVersion")
                    if app.responds(to: verSel),
                       let ver = app.perform(verSel)?.takeUnretainedValue() as? String {
                        appInfo["version"] = ver
                    }

                    // shortVersionString
                    let shortVerSel = NSSelectorFromString("shortVersionString")
                    if app.responds(to: shortVerSel),
                       let sver = app.perform(shortVerSel)?.takeUnretainedValue() as? String {
                        appInfo["shortVersion"] = sver
                    }

                    // vendorName
                    let vendorSel = NSSelectorFromString("vendorName")
                    if app.responds(to: vendorSel),
                       let vendor = app.perform(vendorSel)?.takeUnretainedValue() as? String {
                        appInfo["vendor"] = vendor
                    }

                    // teamID
                    let teamSel = NSSelectorFromString("teamID")
                    if app.responds(to: teamSel),
                       let team = app.perform(teamSel)?.takeUnretainedValue() as? String {
                        appInfo["teamID"] = team
                    }

                    engine.report(module: name, key: "installed_app.\(idx)", value: appInfo)
                }
            } else {
                engine.reportError(module: name, key: "allApplications", error: "returned nil or wrong type")
            }
        } else {
            engine.report(module: name, key: "allApplications", value: "selector_not_available")
        }

        // Try allInstalledApplications
        let allInstalledSel = NSSelectorFromString("allInstalledApplications")
        if (workspace as AnyObject).responds(to: allInstalledSel) {
            if let apps = (workspace as AnyObject).perform(allInstalledSel)?.takeUnretainedValue() as? [AnyObject] {
                engine.report(module: name, key: "all_installed_count", value: apps.count)
            }
        }

        // Try installedPlugins
        let pluginsSel = NSSelectorFromString("installedPlugins")
        if (workspace as AnyObject).responds(to: pluginsSel) {
            if let plugins = (workspace as AnyObject).perform(pluginsSel)?.takeUnretainedValue() as? [AnyObject] {
                engine.report(module: name, key: "installed_plugins_count", value: plugins.count)
            }
        }
    }

    // MARK: - Open URL capabilities

    private func probeOpenURLCapabilities(engine: ReconEngine) {
        // Check UIApplication state
        var appState: String = "unknown"
        if Thread.isMainThread {
            appState = describeAppState(UIApplication.shared.applicationState)
        } else {
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                appState = self.describeAppState(UIApplication.shared.applicationState)
                semaphore.signal()
            }
            semaphore.wait()
        }
        engine.report(module: name, key: "app_state", value: appState)

        // Check what the app's Info.plist declares for LSApplicationQueriesSchemes
        if let queries = Bundle.main.object(forInfoDictionaryKey: "LSApplicationQueriesSchemes") as? [String] {
            engine.report(module: name, key: "declared_query_schemes", value: queries)
        } else {
            engine.report(module: name, key: "declared_query_schemes", value: "none declared in Info.plist")
        }

        // Check CFBundleURLTypes (URL types this app handles)
        if let urlTypes = Bundle.main.object(forInfoDictionaryKey: "CFBundleURLTypes") as? [[String: Any]] {
            engine.report(module: name, key: "registered_url_types", value: urlTypes)
        } else {
            engine.report(module: name, key: "registered_url_types", value: "none")
        }
    }

    private func describeAppState(_ state: UIApplication.State) -> String {
        switch state {
        case .active: return "active"
        case .inactive: return "inactive"
        case .background: return "background"
        @unknown default: return "unknown(\(state.rawValue))"
        }
    }
}
