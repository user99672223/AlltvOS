// SystemInfoModule.swift
// Collects basic device, process, and locale information.
// Reveals device identity, OS version, runtime environment variables,
// thermal state, and locale settings — the foundation for understanding
// what the sandbox can see about its host.

import Foundation
import UIKit

final class SystemInfoModule: ReconModule {
    let name = "SystemInfo"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        collectUIDevice(engine: engine)
        collectProcessInfo(engine: engine)
        collectLocale(engine: engine)
    }

    private func collectUIDevice(engine: ReconEngine) {
        let d = UIDevice.current
        engine.report(module: name, key: "UIDevice.name", value: d.name)
        engine.report(module: name, key: "UIDevice.systemName", value: d.systemName)
        engine.report(module: name, key: "UIDevice.systemVersion", value: d.systemVersion)
        engine.report(module: name, key: "UIDevice.model", value: d.model)
        engine.report(module: name, key: "UIDevice.localizedModel", value: d.localizedModel)
        engine.report(module: name, key: "UIDevice.identifierForVendor", value: d.identifierForVendor?.uuidString ?? "nil")

        let idiom: String
        switch d.userInterfaceIdiom {
        case .tv: idiom = "tv"
        case .phone: idiom = "phone"
        case .pad: idiom = "pad"
        case .carPlay: idiom = "carPlay"
        case .mac: idiom = "mac"
        case .unspecified: idiom = "unspecified"
        @unknown default: idiom = "unknown(\(d.userInterfaceIdiom.rawValue))"
        }
        engine.report(module: name, key: "UIDevice.userInterfaceIdiom", value: idiom)
    }

    private func collectProcessInfo(engine: ReconEngine) {
        let p = ProcessInfo.processInfo
        engine.report(module: name, key: "ProcessInfo.hostName", value: p.hostName)
        engine.report(module: name, key: "ProcessInfo.operatingSystemVersionString", value: p.operatingSystemVersionString)
        let v = p.operatingSystemVersion
        engine.report(module: name, key: "ProcessInfo.operatingSystemVersion", value: "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)")
        engine.report(module: name, key: "ProcessInfo.processorCount", value: p.processorCount)
        engine.report(module: name, key: "ProcessInfo.activeProcessorCount", value: p.activeProcessorCount)
        engine.report(module: name, key: "ProcessInfo.physicalMemory", value: p.physicalMemory)
        engine.report(module: name, key: "ProcessInfo.systemUptime", value: p.systemUptime)
        engine.report(module: name, key: "ProcessInfo.globallyUniqueString", value: p.globallyUniqueString)
        engine.report(module: name, key: "ProcessInfo.processName", value: p.processName)
        engine.report(module: name, key: "ProcessInfo.processIdentifier", value: p.processIdentifier)

        let thermalState: String
        switch p.thermalState {
        case .nominal: thermalState = "nominal"
        case .fair: thermalState = "fair"
        case .serious: thermalState = "serious"
        case .critical: thermalState = "critical"
        @unknown default: thermalState = "unknown(\(p.thermalState.rawValue))"
        }
        engine.report(module: name, key: "ProcessInfo.thermalState", value: thermalState)
        engine.report(module: name, key: "ProcessInfo.isLowPowerModeEnabled", value: p.isLowPowerModeEnabled)

        #if targetEnvironment(macCatalyst)
        engine.report(module: name, key: "ProcessInfo.isMacCatalystApp", value: true)
        #else
        engine.report(module: name, key: "ProcessInfo.isMacCatalystApp", value: false)
        #endif

        if #available(tvOS 14.0, *) {
            engine.report(module: name, key: "ProcessInfo.isiOSAppOnMac", value: p.isiOSAppOnMac)
        } else {
            engine.report(module: name, key: "ProcessInfo.isiOSAppOnMac", value: "unavailable")
        }

        // All environment variables
        let env = p.environment
        engine.report(module: name, key: "ProcessInfo.environment.count", value: env.count)
        for (k, v) in env.sorted(by: { $0.key < $1.key }) {
            engine.report(module: name, key: "ProcessInfo.environment.\(k)", value: v)
        }

        // Arguments
        engine.report(module: name, key: "ProcessInfo.arguments", value: p.arguments)
    }

    private func collectLocale(engine: ReconEngine) {
        let loc = Locale.current
        engine.report(module: name, key: "Locale.identifier", value: loc.identifier)
        engine.report(module: name, key: "Locale.preferredLanguages", value: Locale.preferredLanguages)
        engine.report(module: name, key: "Locale.languageCode", value: loc.languageCode ?? "nil")
        engine.report(module: name, key: "Locale.regionCode", value: loc.regionCode ?? "nil")
        engine.report(module: name, key: "Locale.currencyCode", value: loc.currencyCode ?? "nil")
        engine.report(module: name, key: "Locale.currencySymbol", value: loc.currencySymbol ?? "nil")
        engine.report(module: name, key: "Locale.calendar.identifier", value: loc.calendar.identifier.debugDescription)
        engine.report(module: name, key: "Locale.collatorIdentifier", value: loc.collatorIdentifier ?? "nil")
        engine.report(module: name, key: "Locale.decimalSeparator", value: loc.decimalSeparator ?? "nil")
        engine.report(module: name, key: "Locale.groupingSeparator", value: loc.groupingSeparator ?? "nil")

        let tz = TimeZone.current
        engine.report(module: name, key: "TimeZone.identifier", value: tz.identifier)
        engine.report(module: name, key: "TimeZone.abbreviation", value: tz.abbreviation() ?? "nil")
        engine.report(module: name, key: "TimeZone.secondsFromGMT", value: tz.secondsFromGMT())
        engine.report(module: name, key: "TimeZone.isDaylightSavingTime", value: tz.isDaylightSavingTime())
    }
}
