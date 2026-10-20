// MediaCapabilitiesModule.swift
// TVOSRecon - Module 24: Media Capabilities
//
// Enumerates all audio/video capabilities of the device including
// capture devices, supported codecs, hardware decode support, audio
// session configuration, display modes, HDR capabilities, and
// registered audio components. Critical for understanding the media
// processing pipeline on Apple TV.

import Foundation
import AVFoundation
import UIKit
import AudioToolbox
import VideoToolbox

final class MediaCapabilitiesModule: ReconModule {
    let name = "MediaCapabilities"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeCaptureDevices(engine: engine)
        probeMediaTypes(engine: engine)
        probeAudioSession(engine: engine)
        probeHardwareDecode(engine: engine)
        probeEncoderSupport(engine: engine)
        probeDisplayCapabilities(engine: engine)
        probeAudioComponents(engine: engine)
    }

    // MARK: - Capture Devices

    private func probeCaptureDevices(engine: ReconEngine) {
        // Apple TV has no cameras, but enumerate to confirm
        let mediaTypes: [AVMediaType] = [.video, .audio, .text, .closedCaption,
                                          .subtitle, .timecode, .metadata,
                                          .muxed, .depthData]

        for mediaType in mediaTypes {
            let discoverySession = AVCaptureDevice.DiscoverySession(
                deviceTypes: [.builtInMicrophone, .builtInWideAngleCamera,
                              .builtInUltraWideCamera, .builtInTelephotoCamera],
                mediaType: mediaType,
                position: .unspecified
            )

            let devices = discoverySession.devices
            if devices.isEmpty {
                engine.report(module: name, key: "capture.\(mediaType.rawValue)", value: "no_devices")
            } else {
                for device in devices {
                    engine.report(module: name, key: "capture.\(mediaType.rawValue).\(device.uniqueID)", value: [
                        "name": device.localizedName,
                        "modelID": device.modelID,
                        "manufacturer": device.manufacturer,
                        "position": device.position.rawValue,
                        "isConnected": device.isConnected,
                        "deviceType": device.deviceType.rawValue
                    ])
                }
            }
        }

        // Authorization status
        for mediaType: AVMediaType in [.video, .audio] {
            let status = AVCaptureDevice.authorizationStatus(for: mediaType)
            let statusStr: String
            switch status {
            case .notDetermined: statusStr = "notDetermined"
            case .restricted: statusStr = "restricted"
            case .denied: statusStr = "denied"
            case .authorized: statusStr = "authorized"
            @unknown default: statusStr = "unknown(\(status.rawValue))"
            }
            engine.report(module: name, key: "capture.auth.\(mediaType.rawValue)", value: statusStr)
        }
    }

    // MARK: - Supported Media Types

    private func probeMediaTypes(engine: ReconEngine) {
        // AV types
        let avTypes = AVURLAsset.audiovisualTypes()
        engine.report(module: name, key: "avTypes.count", value: avTypes.count)
        engine.report(module: name, key: "avTypes", value: avTypes.map { $0.rawValue })

        // MIME types
        let mimeTypes = AVURLAsset.audiovisualMIMETypes()
        engine.report(module: name, key: "mimeTypes.count", value: mimeTypes.count)
        engine.report(module: name, key: "mimeTypes", value: mimeTypes)
    }

    // MARK: - Audio Session

    private func probeAudioSession(engine: ReconEngine) {
        let session = AVAudioSession.sharedInstance()

        engine.report(module: name, key: "audio.category", value: session.category.rawValue)
        engine.report(module: name, key: "audio.mode", value: session.mode.rawValue)
        engine.report(module: name, key: "audio.sampleRate", value: session.sampleRate)
        engine.report(module: name, key: "audio.preferredSampleRate", value: session.preferredSampleRate)
        engine.report(module: name, key: "audio.outputVolume", value: session.outputVolume)
        engine.report(module: name, key: "audio.outputNumberOfChannels", value: session.outputNumberOfChannels)
        engine.report(module: name, key: "audio.maximumOutputNumberOfChannels", value: session.maximumOutputNumberOfChannels)
        engine.report(module: name, key: "audio.inputNumberOfChannels", value: session.inputNumberOfChannels)
        engine.report(module: name, key: "audio.ioBufferDuration", value: session.ioBufferDuration)
        engine.report(module: name, key: "audio.preferredIOBufferDuration", value: session.preferredIOBufferDuration)
        engine.report(module: name, key: "audio.isOtherAudioPlaying", value: session.isOtherAudioPlaying)
        engine.report(module: name, key: "audio.secondaryAudioShouldBeSilencedHint", value: session.secondaryAudioShouldBeSilencedHint)
        engine.report(module: name, key: "audio.outputLatency", value: session.outputLatency)
        engine.report(module: name, key: "audio.inputLatency", value: session.inputLatency)

        // Available categories
        let categories: [AVAudioSession.Category] = [
            .ambient, .soloAmbient, .playback, .record,
            .playAndRecord, .multiRoute
        ]

        for cat in categories {
            do {
                try session.setCategory(cat)
                engine.report(module: name, key: "audio.category_test.\(cat.rawValue)", value: "succeeded")
            } catch {
                engine.report(module: name, key: "audio.category_test.\(cat.rawValue)", value: "failed: \(error.localizedDescription)")
            }
        }

        // Restore default
        try? session.setCategory(.playback)

        // Available modes
        let modes: [AVAudioSession.Mode] = [
            .default, .voiceChat, .gameChat, .videoRecording,
            .measurement, .moviePlayback, .videoChat, .spokenAudio
        ]

        for mode in modes {
            do {
                try session.setMode(mode)
                engine.report(module: name, key: "audio.mode_test.\(mode.rawValue)", value: "succeeded")
            } catch {
                engine.report(module: name, key: "audio.mode_test.\(mode.rawValue)", value: "failed: \(error.localizedDescription)")
            }
        }

        try? session.setMode(.default)

        // Current route
        let route = session.currentRoute
        for output in route.outputs {
            engine.report(module: name, key: "audio.route.output.\(output.uid)", value: [
                "name": output.portName,
                "type": output.portType.rawValue,
                "channels": output.channels?.count ?? 0
            ])
        }

        for input in route.inputs {
            engine.report(module: name, key: "audio.route.input.\(input.uid)", value: [
                "name": input.portName,
                "type": input.portType.rawValue,
                "channels": input.channels?.count ?? 0,
                "dataSources": input.dataSources?.count ?? 0,
                "selectedDataSource": input.selectedDataSource?.dataSourceName ?? "none"
            ])
        }

        // Available inputs
        if let inputs = session.availableInputs {
            engine.report(module: name, key: "audio.availableInputs.count", value: inputs.count)
            for input in inputs {
                engine.report(module: name, key: "audio.availableInput.\(input.uid)", value: [
                    "name": input.portName,
                    "type": input.portType.rawValue,
                    "dataSources": input.dataSources?.count ?? 0
                ])
            }
        }

        // Spatial audio
        if #available(tvOS 15.0, *) {
            engine.report(module: name, key: "audio.supportsSpatialAudio",
                          value: session.currentRoute.outputs.first?.isSpatialAudioEnabled ?? false)
        }
    }

    // MARK: - Hardware Decode

    private func probeHardwareDecode(engine: ReconEngine) {
        let codecs: [(String, CMVideoCodecType)] = [
            ("H264", kCMVideoCodecType_H264),
            ("HEVC", kCMVideoCodecType_HEVC),
            ("VP9", CMVideoCodecType(rawValue: "vp09")),
            ("MPEG4", kCMVideoCodecType_MPEG4Video),
            ("JPEG", kCMVideoCodecType_JPEG),
            ("MPEG2", kCMVideoCodecType_MPEG2Video),
            ("AppleProRes422", kCMVideoCodecType_AppleProRes422),
            ("AppleProRes4444", kCMVideoCodecType_AppleProRes4444),
        ]

        // AV1 may not be a defined constant on all SDK versions
        let av1Type = CMVideoCodecType(rawValue: "av01")

        for (label, codec) in codecs {
            let supported = VTIsHardwareDecodeSupported(codec)
            engine.report(module: name, key: "hwdecode.\(label)", value: supported)
        }

        // AV1 separately
        let av1Supported = VTIsHardwareDecodeSupported(av1Type)
        engine.report(module: name, key: "hwdecode.AV1", value: av1Supported)

        // Dolby Vision
        let dvType = CMVideoCodecType(rawValue: "dvh1")
        let dvSupported = VTIsHardwareDecodeSupported(dvType)
        engine.report(module: name, key: "hwdecode.DolbyVision", value: dvSupported)
    }

    // MARK: - Encoder Support

    private func probeEncoderSupport(engine: ReconEngine) {
        let encoderCodecs: [(String, CMVideoCodecType)] = [
            ("H264", kCMVideoCodecType_H264),
            ("HEVC", kCMVideoCodecType_HEVC),
            ("JPEG", kCMVideoCodecType_JPEG),
        ]

        for (label, codec) in encoderCodecs {
            var dict: CFDictionary?
            let status = VTCopySupportedPropertyDictionaryForEncoder(
                width: 1920,
                height: 1080,
                codecType: codec,
                encoderSpecification: nil,
                encoderIDOut: nil,
                supportedPropertiesOut: &dict
            )

            if status == noErr, let props = dict as? [String: Any] {
                let propertyKeys = Array(props.keys)
                engine.report(module: name, key: "encoder.\(label).supported", value: true)
                engine.report(module: name, key: "encoder.\(label).properties_count", value: propertyKeys.count)
                engine.report(module: name, key: "encoder.\(label).properties", value: propertyKeys)
            } else {
                engine.report(module: name, key: "encoder.\(label).supported", value: false)
                engine.report(module: name, key: "encoder.\(label).status", value: status)
            }
        }
    }

    // MARK: - Display Capabilities

    private func probeDisplayCapabilities(engine: ReconEngine) {
        var screens: [UIScreen] = []
        if Thread.isMainThread {
            screens = UIScreen.screens
        } else {
            let sem = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                screens = UIScreen.screens
                sem.signal()
            }
            sem.wait()
        }

        engine.report(module: name, key: "display.screenCount", value: screens.count)

        for (idx, screen) in screens.enumerated() {
            var info: [String: Any] = [:]

            let readBlock = {
                info["bounds"] = "\(screen.bounds)"
                info["nativeBounds"] = "\(screen.nativeBounds)"
                info["scale"] = screen.scale
                info["nativeScale"] = screen.nativeScale
                info["maximumFramesPerSecond"] = screen.maximumFramesPerSecond

                if let mode = screen.currentMode {
                    info["currentMode.size"] = "\(mode.size)"
                }

                if let preferred = screen.preferredMode {
                    info["preferredMode.size"] = "\(preferred.size)"
                }

                // All available modes
                var modes: [[String: Any]] = []
                for mode in screen.availableModes {
                    modes.append([
                        "size": "\(mode.size)",
                        "pixelAspectRatio": mode.pixelAspectRatio
                    ])
                }
                info["availableModes"] = modes
                info["availableModes.count"] = modes.count

                // Overscan
                info["overscanCompensation"] = screen.overscanCompensation.rawValue
                info["overscanCompensationInsets"] = "\(screen.overscanCompensationInsets)"

                // Trait collection
                let tc = screen.traitCollection
                info["displayGamut"] = tc.displayGamut.rawValue
                info["userInterfaceStyle"] = tc.userInterfaceStyle.rawValue
                info["userInterfaceIdiom"] = tc.userInterfaceIdiom.rawValue
                info["displayScale"] = tc.displayScale
                info["layoutDirection"] = tc.layoutDirection.rawValue
                info["forceTouchCapability"] = tc.forceTouchCapability.rawValue
                info["preferredContentSizeCategory"] = tc.preferredContentSizeCategory.rawValue

                // HDR
                info["wantsSoftwareDimming"] = screen.wantsSoftwareDimming

                if #available(tvOS 16.0, *) {
                    info["referenceDisplayModeStatus"] = screen.referenceDisplayModeStatus.rawValue
                    info["currentEDRHeadroom"] = screen.currentEDRHeadroom
                    info["potentialEDRHeadroom"] = screen.potentialEDRHeadroom
                }

                info["calibratedLatency"] = screen.calibratedLatency
            }

            if Thread.isMainThread {
                readBlock()
            } else {
                let sem = DispatchSemaphore(value: 0)
                DispatchQueue.main.async {
                    readBlock()
                    sem.signal()
                }
                sem.wait()
            }

            engine.report(module: name, key: "display.screen.\(idx)", value: info)
        }
    }

    // MARK: - Audio Components

    private func probeAudioComponents(engine: ReconEngine) {
        // Enumerate all audio components
        var desc = AudioComponentDescription()
        desc.componentType = 0
        desc.componentSubType = 0
        desc.componentManufacturer = 0
        desc.componentFlags = 0
        desc.componentFlagsMask = 0

        var totalCount: UInt32 = 0
        var component: AudioComponent? = AudioComponentFindNext(nil, &desc)
        var components: [[String: Any]] = []

        while let comp = component {
            totalCount += 1

            var compDesc = AudioComponentDescription()
            let status = AudioComponentGetDescription(comp, &compDesc)

            if status == noErr {
                var compName: CFString?
                AudioComponentCopyName(comp, &compName)

                let info: [String: Any] = [
                    "name": (compName as String?) ?? "unknown",
                    "type": fourCharString(compDesc.componentType),
                    "subType": fourCharString(compDesc.componentSubType),
                    "manufacturer": fourCharString(compDesc.componentManufacturer),
                    "flags": compDesc.componentFlags
                ]
                components.append(info)

                if totalCount <= 200 {
                    engine.report(module: name, key: "audioComponent.\(totalCount)", value: info)
                }
            }

            component = AudioComponentFindNext(comp, &desc)
        }

        engine.report(module: name, key: "audioComponents.totalCount", value: totalCount)

        // Count by type
        var typeCounts: [String: Int] = [:]
        for comp in components {
            if let type = comp["type"] as? String {
                typeCounts[type, default: 0] += 1
            }
        }
        engine.report(module: name, key: "audioComponents.byType", value: typeCounts)

        // Check specific component types
        let specificTypes: [(String, UInt32, UInt32)] = [
            ("output.default", kAudioUnitType_Output, kAudioUnitSubType_DefaultOutput),
            ("output.remote_io", kAudioUnitType_Output, kAudioUnitSubType_RemoteIO),
            ("effect.eq", kAudioUnitType_Effect, kAudioUnitSubType_BandPassFilter),
            ("effect.reverb", kAudioUnitType_Effect, kAudioUnitSubType_Reverb2),
            ("mixer.multichannel", kAudioUnitType_Mixer, kAudioUnitSubType_MultiChannelMixer),
            ("converter.au", kAudioUnitType_FormatConverter, kAudioUnitSubType_AUConverter),
        ]

        for (label, type, subType) in specificTypes {
            var specificDesc = AudioComponentDescription()
            specificDesc.componentType = type
            specificDesc.componentSubType = subType
            specificDesc.componentManufacturer = 0
            specificDesc.componentFlags = 0
            specificDesc.componentFlagsMask = 0

            let comp = AudioComponentFindNext(nil, &specificDesc)
            engine.report(module: name, key: "audioComponent.specific.\(label)", value: comp != nil ? "available" : "not_found")
        }
    }

    private func fourCharString(_ val: UInt32) -> String {
        let bytes = [
            UInt8((val >> 24) & 0xFF),
            UInt8((val >> 16) & 0xFF),
            UInt8((val >> 8) & 0xFF),
            UInt8(val & 0xFF)
        ]
        if let str = String(bytes: bytes, encoding: .ascii), str.allSatisfy({ $0.isASCII && !$0.isNewline }) {
            return str
        }
        return String(format: "0x%08X", val)
    }
}

extension CMVideoCodecType {
    init(rawValue: String) {
        let chars = Array(rawValue.utf8)
        var val: FourCharCode = 0
        for i in 0..<min(4, chars.count) {
            val = (val << 8) | FourCharCode(chars[i])
        }
        self = val
    }
}
