// DarwinNotificationsModule.swift
// TVOSRecon - Module 20: Darwin Notifications
//
// Probes the Darwin notification center to discover which system-level
// notifications a sandboxed app can observe and post. Notifications
// reveal system state changes (lock, thermal, power, display) and can
// indicate attack surfaces for cross-process information leaks.

import Foundation

final class DarwinNotificationsModule: ReconModule {
    let name = "DarwinNotifications"
    let timeout: TimeInterval = 30

    private var firedNotifications: [String: Int] = [:]
    private let lock = NSLock()

    func run(engine: ReconEngine) {
        probeDarwinCenter(engine: engine)
        probeLocalCenter(engine: engine)
        probeDistributedCenter(engine: engine)
    }

    // MARK: - Darwin Notification Center

    private func probeDarwinCenter(engine: ReconEngine) {
        let center = CFNotificationCenterGetDarwinNotifyCenter()

        let notificationNames: [String] = [
            // SpringBoard
            "com.apple.springboard.lockcomplete",
            "com.apple.springboard.lockstate",
            "com.apple.springboard.hasBlankedScreen",
            "com.apple.springboard.pluggedin",
            "com.apple.springboard.unplugged",
            // Backboard
            "com.apple.backboardd.orientation",
            "com.apple.backboardd.brightness",
            // System state
            "com.apple.system.lowpowermode",
            "com.apple.system.thermalpressure",
            "com.apple.system.config.network_change",
            "com.apple.system.clock_set",
            // IOKit / HID
            "com.apple.iokit.hid.displayStatus",
            "com.apple.iokit.hid.headphoneJack",
            // Keybag
            "com.apple.mobile.keybagd.changed",
            "com.apple.mobile.keybagd.locked",
            "com.apple.mobile.keybagd.unlocked",
            // Application lifecycle
            "com.apple.mobile.application_installed",
            "com.apple.mobile.application_uninstalled",
            // Media services
            "com.apple.mediaserverd.routechange",
            "com.apple.mediaserverd.mutechange",
            "com.apple.mediaserverd.volumechange",
            // CoreMedia
            "com.apple.coremedia.playbackended",
            "com.apple.coremedia.routechange",
            // Audio
            "com.apple.audio.serverrunning",
            "com.apple.audio.route_change",
            "com.apple.audio.interruption",
            "com.apple.audio.volume_change",
            // tvOS specific
            "com.apple.tv.focuschange",
            "com.apple.tv.screensaver.will_start",
            "com.apple.tv.screensaver.did_start",
            "com.apple.tv.screensaver.will_stop",
            "com.apple.tv.screensaver.did_stop",
            "com.apple.tv.remote.connection",
            "com.apple.tv.airplay.status",
            // PineBoard (tvOS SpringBoard)
            "com.apple.pineboard.launched",
            "com.apple.pineboard.applaunch",
            "com.apple.pineboard.homescreen",
            "com.apple.pineboard.focus",
            // Misc
            "com.apple.language.changed",
            "com.apple.AddressBook.PreferenceChanged",
            "com.apple.MobileAsset.asset_ready",
            "com.apple.cfprefsd.daemon.changed",
            "com.apple.locationd.status",
            "com.apple.accessibility.voiceover.status"
        ]

        // Register observers for all
        firedNotifications = [:]

        // We use the module instance as observer context via a global-ish mechanism.
        // Darwin notifications don't support userInfo, so we use CFNotificationCallback.
        let observer = Unmanaged.passUnretained(self).toOpaque()

        for noteName in notificationNames {
            CFNotificationCenterAddObserver(
                center,
                observer,
                darwinNotificationCallback,
                noteName as CFString,
                nil,
                .deliverImmediately
            )
        }

        engine.report(module: name, key: "darwin_registered_count", value: notificationNames.count)

        // Try posting each and check if delivered back to self
        for noteName in notificationNames {
            firedNotifications[noteName] = 0
        }

        for noteName in notificationNames {
            CFNotificationCenterPostNotification(
                center,
                CFNotificationName(rawValue: noteName as CFString),
                nil,
                nil,
                true
            )
        }

        // Give a moment for immediate delivery
        RunLoop.current.run(until: Date().addingTimeInterval(0.5))

        // Report which self-posted notifications were received
        lock.lock()
        let selfPosted = firedNotifications
        lock.unlock()

        var deliveredCount = 0
        for (noteName, count) in selfPosted.sorted(by: { $0.key < $1.key }) {
            if count > 0 {
                engine.report(module: name, key: "darwin_selfpost.\(noteName)", value: "delivered count=\(count)")
                deliveredCount += 1
            } else {
                engine.report(module: name, key: "darwin_selfpost.\(noteName)", value: "not_delivered")
            }
        }
        engine.report(module: name, key: "darwin_selfpost_delivered_count", value: deliveredCount)

        // Now observe for external notifications for 10 seconds
        // Reset counters
        lock.lock()
        for key in firedNotifications.keys {
            firedNotifications[key] = 0
        }
        lock.unlock()

        engine.report(module: name, key: "darwin_observation", value: "listening for 10 seconds...")

        let deadline = Date().addingTimeInterval(10.0)
        while Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.5))
        }

        // Report any external notifications received
        lock.lock()
        let externalFired = firedNotifications
        lock.unlock()

        var externalCount = 0
        for (noteName, count) in externalFired.sorted(by: { $0.key < $1.key }) {
            if count > 0 {
                engine.report(module: name, key: "darwin_external.\(noteName)", value: "fired count=\(count)")
                externalCount += 1
            }
        }
        engine.report(module: name, key: "darwin_external_fired_count", value: externalCount)

        // Remove all observers
        CFNotificationCenterRemoveEveryObserver(center, observer)

        // Also try registering with notify_register_dispatch
        probeNotifyAPI(engine: engine, names: notificationNames)
    }

    private func probeNotifyAPI(engine: ReconEngine, names: [String]) {
        // Try notify_register_check for a few important ones
        typealias NotifyRegCheck = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<Int32>) -> UInt32
        typealias NotifyCheck = @convention(c) (Int32, UnsafeMutablePointer<Int32>) -> UInt32
        typealias NotifyCancel = @convention(c) (Int32) -> UInt32
        typealias NotifyGetState = @convention(c) (Int32, UnsafeMutablePointer<UInt64>) -> UInt32

        guard let regCheckSym = dlsym(dlopen(nil, RTLD_LAZY), "notify_register_check"),
              let checkSym = dlsym(dlopen(nil, RTLD_LAZY), "notify_check"),
              let cancelSym = dlsym(dlopen(nil, RTLD_LAZY), "notify_cancel"),
              let getStateSym = dlsym(dlopen(nil, RTLD_LAZY), "notify_get_state") else {
            engine.report(module: name, key: "notify_api", value: "symbols not found")
            return
        }

        let regCheck = unsafeBitCast(regCheckSym, to: NotifyRegCheck.self)
        let check = unsafeBitCast(checkSym, to: NotifyCheck.self)
        let cancel = unsafeBitCast(cancelSym, to: NotifyCancel.self)
        let getState = unsafeBitCast(getStateSym, to: NotifyGetState.self)

        let sampleNames = Array(names.prefix(10))
        for noteName in sampleNames {
            var token: Int32 = 0
            let regResult = regCheck(noteName, &token)
            if regResult == 0 {  // NOTIFY_STATUS_OK
                var changed: Int32 = 0
                _ = check(token, &changed)

                var state: UInt64 = 0
                let stateResult = getState(token, &state)

                engine.report(module: name, key: "notify_check.\(noteName)",
                              value: "registered token=\(token) changed=\(changed) state=\(state) state_err=\(stateResult)")

                cancel(token)
            } else {
                engine.report(module: name, key: "notify_check.\(noteName)", value: "register_failed status=\(regResult)")
            }
        }
    }

    // MARK: - Local Notification Center

    private func probeLocalCenter(engine: ReconEngine) {
        let localCenter = CFNotificationCenterGetLocalCenter()
        engine.report(module: name, key: "local_center", value: localCenter != nil ? "available" : "nil")

        if localCenter != nil {
            // Post and observe a test notification
            let testName = "com.tvosrecon.localtest" as CFString
            var received = false

            let observer = Unmanaged.passUnretained(self).toOpaque()
            CFNotificationCenterAddObserver(localCenter, observer, { center, obs, noteName, obj, userInfo in
                // Mark as received via side effect
            }, testName, nil, .deliverImmediately)

            CFNotificationCenterPostNotification(localCenter, CFNotificationName(rawValue: testName), nil, nil, true)
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))

            // We can't easily get the callback result here without more state, but log the attempt
            engine.report(module: name, key: "local_center_post", value: "post_succeeded")
            CFNotificationCenterRemoveEveryObserver(localCenter, observer)
        }
    }

    // MARK: - Distributed Notification Center

    private func probeDistributedCenter(engine: ReconEngine) {
        // CFNotificationCenterGetDistributedCenter is macOS only
        // On tvOS this should be nil or crash — test safely via dlsym
        typealias GetDistFunc = @convention(c) () -> CFNotificationCenter?
        if let sym = dlsym(dlopen(nil, RTLD_LAZY), "CFNotificationCenterGetDistributedCenter") {
            let getDistributed = unsafeBitCast(sym, to: GetDistFunc.self)
            let distCenter = getDistributed()
            engine.report(module: name, key: "distributed_center", value: distCenter != nil ? "available" : "nil")
        } else {
            engine.report(module: name, key: "distributed_center", value: "symbol_not_found — not available on tvOS")
        }

        // Also check NSDistributedNotificationCenter via ObjC runtime
        if let cls = NSClassFromString("NSDistributedNotificationCenter") {
            engine.report(module: name, key: "NSDistributedNotificationCenter", value: "class exists: \(cls)")
        } else {
            engine.report(module: name, key: "NSDistributedNotificationCenter", value: "class not found")
        }
    }

    // MARK: - Notification callback tracking

    func recordNotification(_ noteName: String) {
        lock.lock()
        firedNotifications[noteName, default: 0] += 1
        lock.unlock()
    }
}

// Global callback — CFNotificationCallback cannot be a closure
private func darwinNotificationCallback(
    center: CFNotificationCenter?,
    observer: UnsafeMutableRawPointer?,
    name: CFNotificationName?,
    object: UnsafeRawPointer?,
    userInfo: CFDictionary?
) {
    guard let observer = observer, let name = name else { return }
    let module = Unmanaged<DarwinNotificationsModule>.fromOpaque(observer).takeUnretainedValue()
    module.recordNotification(name.rawValue as String)
}
