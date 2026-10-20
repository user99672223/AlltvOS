// HardwareProbeModule.swift
// TVOSRecon
//
// Probes hardware capabilities and sensor availability on Apple TV.
// Apple TV 4K lacks cameras and most motion sensors, but the audio
// subsystem, display capabilities, Bluetooth, and external accessory
// support are all informative. Security researchers should look for:
// unexpected sensor availability, display configuration details that
// reveal hardware model, Bluetooth state that could enable proximity
// attacks, and connected accessories that expand the attack surface.

import Foundation
import UIKit
import AVFoundation
#if canImport(CoreMotion)
import CoreMotion
#endif
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif
#if canImport(ExternalAccessory)
import ExternalAccessory
#endif
#if canImport(CoreLocation)
import CoreLocation
#endif

final class HardwareProbeModule: ReconModule {
    let name = "HardwareProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeMotionSensors(engine: engine)
        probeAudioSession(engine: engine)
        probeCaptureDevices(engine: engine)
        probeScreen(engine: engine)
        probeBluetooth(engine: engine)
        probeExternalAccessories(engine: engine)
        probeLocation(engine: engine)
    }

    // MARK: - CoreMotion

    private func probeMotionSensors(engine: ReconEngine) {
        #if canImport(CoreMotion)
        let motion = CMMotionManager()
        engine.report(module: name, key: "coreMotion.isAccelerometerAvailable", value: motion.isAccelerometerAvailable)
        engine.report(module: name, key: "coreMotion.isGyroAvailable", value: motion.isGyroAvailable)
        engine.report(module: name, key: "coreMotion.isMagnetometerAvailable", value: motion.isMagnetometerAvailable)
        engine.report(module: name, key: "coreMotion.isDeviceMotionAvailable", value: motion.isDeviceMotionAvailable)
        engine.report(module: name, key: "coreMotion.accelerometerUpdateInterval", value: motion.accelerometerUpdateInterval)
        engine.report(module: name, key: "coreMotion.gyroUpdateInterval", value: motion.gyroUpdateInterval)

        if motion.isAccelerometerAvailable {
            engine.report(module: name, key: "coreMotion.accelerometerData", value: motion.accelerometerData != nil ? "available" : "nil")
        }

        if #available(tvOS 15.0, *) {
            engine.report(module: name, key: "coreMotion.isAbsoluteAltitudeAvailable", value: "check_skipped_tvOS")
        }

        if CMMotionActivityManager.isActivityAvailable() {
            engine.report(module: name, key: "coreMotion.isActivityAvailable", value: true)
        } else {
            engine.report(module: name, key: "coreMotion.isActivityAvailable", value: false)
        }

        engine.report(module: name, key: "coreMotion.isPedometerAvailable.stepCounting",
                      value: CMPedometer.isStepCountingAvailable())
        engine.report(module: name, key: "coreMotion.isPedometerAvailable.distance",
                      value: CMPedometer.isDistanceAvailable())
        engine.report(module: name, key: "coreMotion.isPedometerAvailable.floorCounting",
                      value: CMPedometer.isFloorCountingAvailable())
        engine.report(module: name, key: "coreMotion.isPedometerAvailable.pace",
                      value: CMPedometer.isPaceAvailable())
        engine.report(module: name, key: "coreMotion.isPedometerAvailable.cadence",
                      value: CMPedometer.isCadenceAvailable())
        #else
        engine.reportError(module: name, key: "coreMotion", error: "CoreMotion not available")
        #endif
    }

    // MARK: - AVAudioSession

    private func probeAudioSession(engine: ReconEngine) {
        do {
            let session = AVAudioSession.sharedInstance()

            engine.report(module: name, key: "audio.category", value: session.category.rawValue)
            engine.report(module: name, key: "audio.mode", value: session.mode.rawValue)
            engine.report(module: name, key: "audio.sampleRate", value: session.sampleRate)
            engine.report(module: name, key: "audio.preferredSampleRate", value: session.preferredSampleRate)
            engine.report(module: name, key: "audio.outputNumberOfChannels", value: session.outputNumberOfChannels)
            engine.report(module: name, key: "audio.maximumOutputNumberOfChannels", value: session.maximumOutputNumberOfChannels)
            engine.report(module: name, key: "audio.inputNumberOfChannels", value: session.inputNumberOfChannels)
            engine.report(module: name, key: "audio.maximumInputNumberOfChannels", value: session.maximumInputNumberOfChannels)
            engine.report(module: name, key: "audio.outputVolume", value: session.outputVolume)
            engine.report(module: name, key: "audio.isOtherAudioPlaying", value: session.isOtherAudioPlaying)
            engine.report(module: name, key: "audio.secondaryAudioShouldBeSilencedHint", value: session.secondaryAudioShouldBeSilencedHint)
            engine.report(module: name, key: "audio.ioBufferDuration", value: session.ioBufferDuration)
            engine.report(module: name, key: "audio.preferredIOBufferDuration", value: session.preferredIOBufferDuration)
            engine.report(module: name, key: "audio.outputLatency", value: session.outputLatency)
            engine.report(module: name, key: "audio.inputLatency", value: session.inputLatency)

            if let inputs = session.availableInputs {
                engine.report(module: name, key: "audio.availableInputs.count", value: inputs.count)
                for (idx, input) in inputs.enumerated() {
                    engine.report(module: name, key: "audio.availableInputs[\(idx)].portName", value: input.portName)
                    engine.report(module: name, key: "audio.availableInputs[\(idx)].portType", value: input.portType.rawValue)
                    engine.report(module: name, key: "audio.availableInputs[\(idx)].uid", value: input.uid)
                    if let channels = input.channels {
                        engine.report(module: name, key: "audio.availableInputs[\(idx)].channels", value: channels.count)
                    }
                    if let dataSources = input.dataSources {
                        for (dsIdx, ds) in dataSources.enumerated() {
                            engine.report(module: name, key: "audio.availableInputs[\(idx)].dataSources[\(dsIdx)].name", value: ds.dataSourceName)
                            engine.report(module: name, key: "audio.availableInputs[\(idx)].dataSources[\(dsIdx)].id", value: ds.dataSourceID)
                        }
                    }
                }
            }

            let route = session.currentRoute
            for (idx, output) in route.outputs.enumerated() {
                engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].portName", value: output.portName)
                engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].portType", value: output.portType.rawValue)
                engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].uid", value: output.uid)
                if let channels = output.channels {
                    engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].channels", value: channels.count)
                    for (chIdx, ch) in channels.enumerated() {
                        engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].channel[\(chIdx)].name", value: ch.channelName)
                        engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].channel[\(chIdx)].number", value: ch.channelNumber)
                        engine.report(module: name, key: "audio.currentRoute.outputs[\(idx)].channel[\(chIdx)].label", value: ch.channelLabel)
                    }
                }
            }
            for (idx, input) in route.inputs.enumerated() {
                engine.report(module: name, key: "audio.currentRoute.inputs[\(idx)].portName", value: input.portName)
                engine.report(module: name, key: "audio.currentRoute.inputs[\(idx)].portType", value: input.portType.rawValue)
                engine.report(module: name, key: "audio.currentRoute.inputs[\(idx)].uid", value: input.uid)
            }

            let categories: [AVAudioSession.Category] = [
                .ambient, .soloAmbient, .playback, .record,
                .playAndRecord, .multiRoute
            ]
            for cat in categories {
                do {
                    try session.setCategory(cat)
                    engine.report(module: name, key: "audio.categoryTest.\(cat.rawValue)", value: "success")
                } catch {
                    engine.report(module: name, key: "audio.categoryTest.\(cat.rawValue)", value: "failed: \(error.localizedDescription)")
                }
            }
            try? session.setCategory(.playback)

        }
    }

    // MARK: - Capture Devices

    private func probeCaptureDevices(engine: ReconEngine) {
        // AVCaptureDevice discovery and authorization APIs are only available from tvOS 17.0.
        if #available(tvOS 17.0, *) {
            let mediaTypes: [AVMediaType] = [.video, .audio, .text, .closedCaption,
                                              .subtitle, .timecode, .metadata,
                                              .depthData]
            for mediaType in mediaTypes {
                // .builtInMicrophone is unavailable on tvOS, so only camera device types are queried.
                let devices = AVCaptureDevice.DiscoverySession(
                    deviceTypes: [.builtInWideAngleCamera],
                    mediaType: mediaType,
                    position: .unspecified
                ).devices
                engine.report(module: name, key: "captureDevice.\(mediaType.rawValue).count", value: devices.count)
                for (idx, device) in devices.enumerated() {
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].name", value: device.localizedName)
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].uniqueID", value: device.uniqueID)
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].modelID", value: device.modelID)
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].manufacturer", value: device.manufacturer)
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].position", value: "\(device.position.rawValue)")
                    engine.report(module: name, key: "captureDevice.\(mediaType.rawValue)[\(idx)].isConnected", value: device.isConnected)
                }
            }

            if let defaultVideo = AVCaptureDevice.default(for: .video) {
                engine.report(module: name, key: "captureDevice.defaultVideo", value: defaultVideo.localizedName)
            } else {
                engine.report(module: name, key: "captureDevice.defaultVideo", value: "none")
            }

            if let defaultAudio = AVCaptureDevice.default(for: .audio) {
                engine.report(module: name, key: "captureDevice.defaultAudio", value: defaultAudio.localizedName)
            } else {
                engine.report(module: name, key: "captureDevice.defaultAudio", value: "none")
            }

            engine.report(module: name, key: "captureDevice.authorizationStatus.video",
                          value: "\(AVCaptureDevice.authorizationStatus(for: .video).rawValue)")
            engine.report(module: name, key: "captureDevice.authorizationStatus.audio",
                          value: "\(AVCaptureDevice.authorizationStatus(for: .audio).rawValue)")
        } else {
            engine.report(module: name, key: "capture_devices", value: "unavailable_before_tvOS_17")
        }
    }

    // MARK: - UIScreen

    private func probeScreen(engine: ReconEngine) {
        DispatchQueue.main.sync {
            let screens = UIScreen.screens
            engine.report(module: name, key: "screen.count", value: screens.count)

            for (idx, screen) in screens.enumerated() {
                let prefix = "screen[\(idx)]"
                engine.report(module: name, key: "\(prefix).bounds", value: "\(screen.bounds)")
                engine.report(module: name, key: "\(prefix).nativeBounds", value: "\(screen.nativeBounds)")
                engine.report(module: name, key: "\(prefix).scale", value: screen.scale)
                engine.report(module: name, key: "\(prefix).nativeScale", value: screen.nativeScale)
                engine.report(module: name, key: "\(prefix).maximumFramesPerSecond", value: screen.maximumFramesPerSecond)
                #if !os(tvOS)
                engine.report(module: name, key: "\(prefix).brightness", value: screen.brightness)
                engine.report(module: name, key: "\(prefix).wantsSoftwareDimming", value: screen.wantsSoftwareDimming)
                #else
                engine.report(module: name, key: "\(prefix).brightness", value: "unavailable_on_tvOS")
                engine.report(module: name, key: "\(prefix).wantsSoftwareDimming", value: "unavailable_on_tvOS")
                #endif
                engine.report(module: name, key: "\(prefix).overscanCompensation", value: screen.overscanCompensation.rawValue)
                engine.report(module: name, key: "\(prefix).calibratedLatency", value: screen.calibratedLatency)

                if let currentMode = screen.currentMode {
                    engine.report(module: name, key: "\(prefix).currentMode.size", value: "\(currentMode.size)")
                    engine.report(module: name, key: "\(prefix).currentMode.pixelAspectRatio", value: currentMode.pixelAspectRatio)
                }

                #if !os(tvOS)
                if let preferredMode = screen.preferredMode {
                    engine.report(module: name, key: "\(prefix).preferredMode.size", value: "\(preferredMode.size)")
                    engine.report(module: name, key: "\(prefix).preferredMode.pixelAspectRatio", value: preferredMode.pixelAspectRatio)
                }

                let modes = screen.availableModes
                engine.report(module: name, key: "\(prefix).availableModes.count", value: modes.count)
                for (mIdx, mode) in modes.enumerated() {
                    engine.report(module: name, key: "\(prefix).availableModes[\(mIdx)].size", value: "\(mode.size)")
                    engine.report(module: name, key: "\(prefix).availableModes[\(mIdx)].pixelAspectRatio", value: mode.pixelAspectRatio)
                }
                #else
                engine.report(module: name, key: "\(prefix).preferredMode", value: "unavailable_on_tvOS")
                engine.report(module: name, key: "\(prefix).availableModes", value: "unavailable_on_tvOS")
                #endif

                let traits = screen.traitCollection
                engine.report(module: name, key: "\(prefix).traitCollection.displayGamut", value: traits.displayGamut.rawValue)
                engine.report(module: name, key: "\(prefix).traitCollection.userInterfaceStyle", value: traits.userInterfaceStyle.rawValue)
                engine.report(module: name, key: "\(prefix).traitCollection.userInterfaceIdiom", value: traits.userInterfaceIdiom.rawValue)
                engine.report(module: name, key: "\(prefix).traitCollection.displayScale", value: traits.displayScale)
                engine.report(module: name, key: "\(prefix).traitCollection.layoutDirection", value: traits.layoutDirection.rawValue)
                engine.report(module: name, key: "\(prefix).traitCollection.forceTouchCapability", value: traits.forceTouchCapability.rawValue)
                engine.report(module: name, key: "\(prefix).traitCollection.preferredContentSizeCategory", value: traits.preferredContentSizeCategory.rawValue)

                if #available(tvOS 17.0, *) {
                    engine.report(module: name, key: "\(prefix).potentiallyHDRContent", value: "check_available")
                }
            }
        }
    }

    // MARK: - Bluetooth

    private func probeBluetooth(engine: ReconEngine) {
        #if canImport(CoreBluetooth)
        let delegate = BTDelegate(engine: engine, moduleName: name)
        let centralManager = CBCentralManager(delegate: delegate, queue: nil,
                                               options: [CBCentralManagerOptionShowPowerAlertKey: false])
        engine.report(module: name, key: "bluetooth.initialState", value: cbStateString(centralManager.state))

        let semaphore = DispatchSemaphore(value: 0)
        delegate.completionHandler = {
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + 8)

        engine.report(module: name, key: "bluetooth.finalState", value: cbStateString(centralManager.state))
        engine.report(module: name, key: "bluetooth.isScanning", value: centralManager.isScanning)
        if #available(tvOS 13.0, *) {
            engine.report(module: name, key: "bluetooth.authorization", value: "\(CBCentralManager.authorization.rawValue)")
        }
        if centralManager.state == .poweredOn {
            engine.report(module: name, key: "bluetooth.peripheralsDiscovered", value: delegate.discoveredCount)
        }
        centralManager.stopScan()
        #else
        engine.reportError(module: name, key: "bluetooth", error: "CoreBluetooth not available")
        #endif
    }

    #if canImport(CoreBluetooth)
    private func cbStateString(_ state: CBManagerState) -> String {
        switch state {
        case .unknown: return "unknown"
        case .resetting: return "resetting"
        case .unsupported: return "unsupported"
        case .unauthorized: return "unauthorized"
        case .poweredOff: return "poweredOff"
        case .poweredOn: return "poweredOn"
        @unknown default: return "unknown(\(state.rawValue))"
        }
    }
    #endif

    // MARK: - External Accessories

    private func probeExternalAccessories(engine: ReconEngine) {
        #if canImport(ExternalAccessory)
        let mgr = EAAccessoryManager.shared()
        let accessories = mgr.connectedAccessories
        engine.report(module: name, key: "externalAccessory.connectedCount", value: accessories.count)
        for (idx, acc) in accessories.enumerated() {
            engine.report(module: name, key: "externalAccessory[\(idx)].name", value: acc.name)
            engine.report(module: name, key: "externalAccessory[\(idx)].manufacturer", value: acc.manufacturer)
            engine.report(module: name, key: "externalAccessory[\(idx)].modelNumber", value: acc.modelNumber)
            engine.report(module: name, key: "externalAccessory[\(idx)].serialNumber", value: acc.serialNumber)
            engine.report(module: name, key: "externalAccessory[\(idx)].firmwareRevision", value: acc.firmwareRevision)
            engine.report(module: name, key: "externalAccessory[\(idx)].hardwareRevision", value: acc.hardwareRevision)
            engine.report(module: name, key: "externalAccessory[\(idx)].isConnected", value: acc.isConnected)
            engine.report(module: name, key: "externalAccessory[\(idx)].connectionID", value: acc.connectionID)
            engine.report(module: name, key: "externalAccessory[\(idx)].protocolStrings", value: acc.protocolStrings.joined(separator: ", "))
        }
        #else
        engine.reportError(module: name, key: "externalAccessory", error: "ExternalAccessory not available")
        #endif
    }

    // MARK: - Location

    private func probeLocation(engine: ReconEngine) {
        #if canImport(CoreLocation)
        let locMgr = CLLocationManager()
        engine.report(module: name, key: "location.locationServicesEnabled", value: CLLocationManager.locationServicesEnabled())
        engine.report(module: name, key: "location.authorizationStatus", value: "\(CLLocationManager.authorizationStatus().rawValue)")
        #if !os(tvOS)
        engine.report(module: name, key: "location.significantLocationChangeMonitoringAvailable",
                      value: CLLocationManager.significantLocationChangeMonitoringAvailable())
        engine.report(module: name, key: "location.headingAvailable", value: CLLocationManager.headingAvailable())
        engine.report(module: name, key: "location.isRangingAvailable", value: CLLocationManager.isRangingAvailable())
        engine.report(module: name, key: "location.isMonitoringAvailableForRegion.circular",
                      value: CLLocationManager.isMonitoringAvailable(for: CLCircularRegion.self))
        #else
        engine.report(module: name, key: "location.significantLocationChangeMonitoringAvailable", value: "unavailable_on_tvOS")
        engine.report(module: name, key: "location.headingAvailable", value: "unavailable_on_tvOS")
        engine.report(module: name, key: "location.isRangingAvailable", value: "unavailable_on_tvOS")
        engine.report(module: name, key: "location.isMonitoringAvailableForRegion.circular", value: "unavailable_on_tvOS")
        #endif
        engine.report(module: name, key: "location.desiredAccuracy", value: locMgr.desiredAccuracy)
        engine.report(module: name, key: "location.distanceFilter", value: locMgr.distanceFilter)
        #if !os(tvOS)
        engine.report(module: name, key: "location.activityType", value: locMgr.activityType.rawValue)
        #else
        engine.report(module: name, key: "location.activityType", value: "unavailable_on_tvOS")
        #endif
        if let location = locMgr.location {
            engine.report(module: name, key: "location.lastKnown.latitude", value: location.coordinate.latitude)
            engine.report(module: name, key: "location.lastKnown.longitude", value: location.coordinate.longitude)
            engine.report(module: name, key: "location.lastKnown.altitude", value: location.altitude)
            engine.report(module: name, key: "location.lastKnown.timestamp", value: ISO8601DateFormatter().string(from: location.timestamp))
        } else {
            engine.report(module: name, key: "location.lastKnown", value: "nil")
        }
        if #available(tvOS 14.0, *) {
            engine.report(module: name, key: "location.accuracyAuthorization", value: "\(locMgr.accuracyAuthorization.rawValue)")
        }
        #else
        engine.reportError(module: name, key: "location", error: "CoreLocation not available")
        #endif
    }
}

// MARK: - Bluetooth Delegate Helper

#if canImport(CoreBluetooth)
private class BTDelegate: NSObject, CBCentralManagerDelegate {
    let engine: ReconEngine
    let moduleName: String
    var discoveredCount = 0
    var completionHandler: (() -> Void)?

    init(engine: ReconEngine, moduleName: String) {
        self.engine = engine
        self.moduleName = moduleName
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        engine.report(module: moduleName, key: "bluetooth.stateUpdate", value: "\(central.state.rawValue)")
        if central.state == .poweredOn {
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
            DispatchQueue.global().asyncAfter(deadline: .now() + 5) { [weak self] in
                self?.completionHandler?()
            }
        } else {
            completionHandler?()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                         advertisementData: [String: Any], rssi RSSI: NSNumber) {
        discoveredCount += 1
        if discoveredCount <= 50 {
            engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].name",
                          value: peripheral.name ?? "unknown")
            engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].rssi",
                          value: RSSI.intValue)
            engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].state",
                          value: "\(peripheral.state.rawValue)")
            if let serviceUUIDs = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
                engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].serviceUUIDs",
                              value: serviceUUIDs.map { $0.uuidString }.joined(separator: ", "))
            }
            if let mfgData = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data {
                engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].mfgData",
                              value: mfgData.base64EncodedString())
            }
            if let txPower = advertisementData[CBAdvertisementDataTxPowerLevelKey] as? NSNumber {
                engine.report(module: moduleName, key: "bluetooth.peripheral[\(discoveredCount)].txPower",
                              value: txPower.intValue)
            }
        }
    }
}
#endif
