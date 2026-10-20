// AccessibilityAndUIProbeModule: Probes accessibility settings, UI traits, and focus system.
// Reveals user preference state and display capabilities relevant to UI attack surface.

import Foundation
import UIKit

final class AccessibilityAndUIProbeModule: ReconModule {
    let name = "AccessibilityAndUIProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeAccessibility(engine: engine)
        probeTraitCollection(engine: engine)
        probeFocusSystem(engine: engine)
    }

    private func probeAccessibility(engine: ReconEngine) {
        // All UIAccessibility calls must be on main thread
        let results: [(String, String)] = DispatchQueue.main.sync {
            var r: [(String, String)] = []
            r.append(("isVoiceOverRunning", "\(UIAccessibility.isVoiceOverRunning)"))
            r.append(("isSwitchControlRunning", "\(UIAccessibility.isSwitchControlRunning)"))
            r.append(("isShakeToUndoEnabled", "\(UIAccessibility.isShakeToUndoEnabled)"))
            r.append(("isBoldTextEnabled", "\(UIAccessibility.isBoldTextEnabled)"))
            r.append(("isReduceMotionEnabled", "\(UIAccessibility.isReduceMotionEnabled)"))
            r.append(("isReduceTransparencyEnabled", "\(UIAccessibility.isReduceTransparencyEnabled)"))
            r.append(("isGrayscaleEnabled", "\(UIAccessibility.isGrayscaleEnabled)"))
            r.append(("isInvertColorsEnabled", "\(UIAccessibility.isInvertColorsEnabled)"))
            r.append(("isDarkerSystemColorsEnabled", "\(UIAccessibility.isDarkerSystemColorsEnabled)"))
            r.append(("isClosedCaptioningEnabled", "\(UIAccessibility.isClosedCaptioningEnabled)"))
            r.append(("preferredContentSizeCategory", UIApplication.shared.preferredContentSizeCategory.rawValue))

            if #available(tvOS 14.0, *) {
                r.append(("buttonShapesEnabled", "\(UIAccessibility.buttonShapesEnabled)"))
                r.append(("prefersCrossFadeTransitions", "\(UIAccessibility.prefersCrossFadeTransitions)"))
            }

            r.append(("isMonoAudioEnabled", "\(UIAccessibility.isMonoAudioEnabled)"))

            return r
        }

        for (key, value) in results {
            engine.report(module: name, key: "accessibility_\(key)", value: value)
        }
    }

    private func probeTraitCollection(engine: ReconEngine) {
        let results: [(String, String)] = DispatchQueue.main.sync {
            var r: [(String, String)] = []

            let traits = UITraitCollection.current

            // Display gamut
            let gamut: String
            switch traits.displayGamut {
            case .SRGB: gamut = "sRGB"
            case .P3:   gamut = "P3"
            case .unspecified: gamut = "unspecified"
            @unknown default: gamut = "unknown(\(traits.displayGamut.rawValue))"
            }
            r.append(("displayGamut", gamut))
            r.append(("displayScale", "\(traits.displayScale)"))

            // Force touch
            let forceTouch: String
            switch traits.forceTouchCapability {
            case .available:   forceTouch = "available"
            case .unavailable: forceTouch = "unavailable"
            case .unknown:     forceTouch = "unknown"
            @unknown default:  forceTouch = "unknown(\(traits.forceTouchCapability.rawValue))"
            }
            r.append(("forceTouchCapability", forceTouch))

            // User interface style
            let style: String
            switch traits.userInterfaceStyle {
            case .dark:         style = "dark"
            case .light:        style = "light"
            case .unspecified:  style = "unspecified"
            @unknown default:   style = "unknown(\(traits.userInterfaceStyle.rawValue))"
            }
            r.append(("userInterfaceStyle", style))

            // Idiom
            let idiom: String
            switch traits.userInterfaceIdiom {
            case .tv:           idiom = "tv"
            case .phone:        idiom = "phone"
            case .pad:          idiom = "pad"
            case .carPlay:      idiom = "carPlay"
            case .mac:          idiom = "mac"
            case .unspecified:  idiom = "unspecified"
            @unknown default:   idiom = "unknown(\(traits.userInterfaceIdiom.rawValue))"
            }
            r.append(("userInterfaceIdiom", idiom))

            // Layout direction
            let dir: String
            switch traits.layoutDirection {
            case .leftToRight:  dir = "leftToRight"
            case .rightToLeft:  dir = "rightToLeft"
            case .unspecified:  dir = "unspecified"
            @unknown default:   dir = "unknown(\(traits.layoutDirection.rawValue))"
            }
            r.append(("layoutDirection", dir))

            // Size classes
            let hClass: String
            switch traits.horizontalSizeClass {
            case .compact:     hClass = "compact"
            case .regular:     hClass = "regular"
            case .unspecified: hClass = "unspecified"
            @unknown default:  hClass = "unknown(\(traits.horizontalSizeClass.rawValue))"
            }
            r.append(("horizontalSizeClass", hClass))

            let vClass: String
            switch traits.verticalSizeClass {
            case .compact:     vClass = "compact"
            case .regular:     vClass = "regular"
            case .unspecified: vClass = "unspecified"
            @unknown default:  vClass = "unknown(\(traits.verticalSizeClass.rawValue))"
            }
            r.append(("verticalSizeClass", vClass))

            r.append(("preferredContentSizeCategory", traits.preferredContentSizeCategory.rawValue))

            // userInterfaceLevel is unavailable on tvOS, so it is only read on other platforms.
            #if !os(tvOS)
            if #available(iOS 13.0, *) {
                let level: String
                switch traits.userInterfaceLevel {
                case .base:        level = "base"
                case .elevated:    level = "elevated"
                case .unspecified: level = "unspecified"
                @unknown default:  level = "unknown(\(traits.userInterfaceLevel.rawValue))"
                }
                r.append(("userInterfaceLevel", level))
            }
            #else
            r.append(("userInterfaceLevel", "unavailable_on_tvOS"))
            #endif

            if #available(tvOS 14.0, *) {
                let contrast: String
                switch traits.activeAppearance {
                case .active:      contrast = "active"
                case .inactive:    contrast = "inactive"
                case .unspecified: contrast = "unspecified"
                @unknown default:  contrast = "unknown(\(traits.activeAppearance.rawValue))"
                }
                r.append(("activeAppearance", contrast))
            }

            return r
        }

        for (key, value) in results {
            engine.report(module: name, key: "trait_\(key)", value: value)
        }
    }

    private func probeFocusSystem(engine: ReconEngine) {
        let results: [(String, String)] = DispatchQueue.main.sync { () -> [(String, String)] in
            var r: [(String, String)] = []

            if #available(tvOS 15.0, *) {
                // focusSystem(for:) expects a UIFocusEnvironment such as a window or view, so use the window, not the scene.
                let windowScenes: [UIWindowScene] = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
                let windows: [UIWindow] = windowScenes.flatMap { $0.windows }
                let window: UIWindow? = windows.first(where: { $0.isKeyWindow }) ?? windows.first
                let focusSystem: UIFocusSystem? = window.flatMap { UIFocusSystem.focusSystem(for: $0) }
                r.append(("focusSystem_available", focusSystem != nil ? "yes" : "no"))
            }

            r.append(("connectedScenes_count", "\(UIApplication.shared.connectedScenes.count)"))
            for scene in UIApplication.shared.connectedScenes {
                let state: String
                switch scene.activationState {
                case .foregroundActive:   state = "foregroundActive"
                case .foregroundInactive: state = "foregroundInactive"
                case .background:         state = "background"
                case .unattached:         state = "unattached"
                @unknown default:         state = "unknown"
                }
                r.append(("scene_\(scene.session.persistentIdentifier)_state", state))
                r.append(("scene_\(scene.session.persistentIdentifier)_role", scene.session.role.rawValue))
            }

            return r
        }

        for (key, value) in results {
            engine.report(module: name, key: "focus_\(key)", value: value)
        }
    }
}
