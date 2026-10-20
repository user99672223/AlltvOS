// MetalGPUProbeModule.swift
// TVOSRecon - Module 23: Metal GPU Probe
//
// Enumerates Metal GPU capabilities, supported pixel formats, shader
// language versions, and GPU family support. The Apple TV 4K uses an
// A15 Bionic with a 5-core GPU. Understanding the GPU's full capability
// set reveals what compute and rendering workloads are possible and
// the exact GPU family/generation.

import Foundation
#if canImport(Metal)
import Metal
#endif

final class MetalGPUProbeModule: ReconModule {
    let name = "MetalGPUProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        #if canImport(Metal)
        probeDevice(engine: engine)
        #else
        engine.reportError(module: name, key: "metal", error: "Metal framework not available")
        #endif
    }

    #if canImport(Metal)
    private func probeDevice(engine: ReconEngine) {
        guard let device = MTLCreateSystemDefaultDevice() else {
            engine.reportError(module: name, key: "device", error: "MTLCreateSystemDefaultDevice returned nil")
            return
        }

        // Basic device info
        engine.report(module: name, key: "device.name", value: device.name)
        engine.report(module: name, key: "device.registryID", value: device.registryID)

        // isLowPower, isRemovable and isHeadless are unavailable on tvOS.
        #if !os(tvOS)
        engine.report(module: name, key: "device.isLowPower", value: device.isLowPower)
        engine.report(module: name, key: "device.isRemovable", value: device.isRemovable)
        engine.report(module: name, key: "device.isHeadless", value: device.isHeadless)
        #endif

        // location and locationNumber are macOS-only (no member on tvOS or iOS).
        #if os(macOS)
        if #available(macOS 10.13, *) {
            engine.report(module: name, key: "device.location", value: device.location.rawValue)
            engine.report(module: name, key: "device.locationNumber", value: device.locationNumber)
        }
        #endif

        // GPU family support
        probeGPUFamilies(device: device, engine: engine)

        // Capabilities
        probeCapabilities(device: device, engine: engine)

        // Pixel formats
        probeSupportedPixelFormats(device: device, engine: engine)

        // Working set sizes
        probeWorkingSets(device: device, engine: engine)

        // Compute pipeline
        probeComputePipeline(device: device, engine: engine)

        // Shader versions
        probeShaderVersions(device: device, engine: engine)

        // Indirect command buffers
        probeIndirectCommandBuffers(device: device, engine: engine)

        // Additional feature queries
        probeAdditionalFeatures(device: device, engine: engine)
    }

    private func probeGPUFamilies(device: MTLDevice, engine: ReconEngine) {
        // Apple families
        let appleFamilies: [(String, MTLGPUFamily)] = [
            ("apple1", .apple1),
            ("apple2", .apple2),
            ("apple3", .apple3),
            ("apple4", .apple4),
            ("apple5", .apple5),
            ("apple6", .apple6),
            ("apple7", .apple7),
            ("apple8", .apple8),
        ]

        for (label, family) in appleFamilies {
            engine.report(module: name, key: "family.\(label)", value: device.supportsFamily(family))
        }

        // apple9 may not be available at compile time
        if #available(tvOS 17.0, *) {
            engine.report(module: name, key: "family.apple9", value: device.supportsFamily(.apple9))
        }

        // Common families
        let commonFamilies: [(String, MTLGPUFamily)] = [
            ("common1", .common1),
            ("common2", .common2),
            ("common3", .common3),
        ]

        for (label, family) in commonFamilies {
            engine.report(module: name, key: "family.\(label)", value: device.supportsFamily(family))
        }

        // Metal 3
        if #available(tvOS 16.0, *) {
            engine.report(module: name, key: "family.metal3", value: device.supportsFamily(.metal3))
        }
    }

    private func probeCapabilities(device: MTLDevice, engine: ReconEngine) {
        engine.report(module: name, key: "caps.maxThreadsPerThreadgroup",
                      value: "\(device.maxThreadsPerThreadgroup)")
        engine.report(module: name, key: "caps.maxThreadgroupMemoryLength",
                      value: device.maxThreadgroupMemoryLength)
        engine.report(module: name, key: "caps.maxBufferLength",
                      value: device.maxBufferLength)

        engine.report(module: name, key: "caps.areRasterOrderGroupsSupported",
                      value: device.areRasterOrderGroupsSupported)
        engine.report(module: name, key: "caps.supports32BitMSAA",
                      value: device.supports32BitMSAA)
        engine.report(module: name, key: "caps.supports32BitFloatFiltering",
                      value: device.supports32BitFloatFiltering)
        if #available(tvOS 16.4, *) {
            engine.report(module: name, key: "caps.supportsBCTextureCompression",
                          value: device.supportsBCTextureCompression)
        }
        engine.report(module: name, key: "caps.supportsQueryTextureLOD",
                      value: device.supportsQueryTextureLOD)
        engine.report(module: name, key: "caps.supportsFunctionPointers",
                      value: device.supportsFunctionPointers)
        engine.report(module: name, key: "caps.supportsDynamicLibraries",
                      value: device.supportsDynamicLibraries)
        engine.report(module: name, key: "caps.supportsRenderDynamicLibraries",
                      value: device.supportsRenderDynamicLibraries)

        if #available(tvOS 16.0, *) {
            engine.report(module: name, key: "caps.supportsRaytracing",
                          value: device.supportsRaytracing)
        }

        engine.report(module: name, key: "caps.areProgrammableSamplePositionsSupported",
                      value: device.areProgrammableSamplePositionsSupported)

        engine.report(module: name, key: "caps.currentAllocatedSize",
                      value: device.currentAllocatedSize)

        if #available(tvOS 16.0, *) {
            engine.report(module: name, key: "caps.supportsPrimitiveMotionBlur",
                          value: device.supportsPrimitiveMotionBlur)
        }

        engine.report(module: name, key: "caps.readWriteTextureSupport",
                      value: device.readWriteTextureSupport.rawValue)
        engine.report(module: name, key: "caps.argumentBuffersSupport",
                      value: device.argumentBuffersSupport.rawValue)
    }

    private func probeSupportedPixelFormats(device: MTLDevice, engine: ReconEngine) {
        // Test a representative set of pixel formats
        var formats: [(String, MTLPixelFormat)] = [
            ("a8Unorm", .a8Unorm),
            ("r8Unorm", .r8Unorm),
            ("r8Snorm", .r8Snorm),
            ("r8Uint", .r8Uint),
            ("r8Sint", .r8Sint),
            ("r16Unorm", .r16Unorm),
            ("r16Snorm", .r16Snorm),
            ("r16Uint", .r16Uint),
            ("r16Sint", .r16Sint),
            ("r16Float", .r16Float),
            ("rg8Unorm", .rg8Unorm),
            ("rg8Snorm", .rg8Snorm),
            ("r32Uint", .r32Uint),
            ("r32Sint", .r32Sint),
            ("r32Float", .r32Float),
            ("rg16Unorm", .rg16Unorm),
            ("rg16Float", .rg16Float),
            ("rgba8Unorm", .rgba8Unorm),
            ("rgba8Unorm_srgb", .rgba8Unorm_srgb),
            ("rgba8Snorm", .rgba8Snorm),
            ("bgra8Unorm", .bgra8Unorm),
            ("bgra8Unorm_srgb", .bgra8Unorm_srgb),
            ("rgb10a2Unorm", .rgb10a2Unorm),
            ("rg11b10Float", .rg11b10Float),
            ("rgb9e5Float", .rgb9e5Float),
            ("rg32Uint", .rg32Uint),
            ("rg32Float", .rg32Float),
            ("rgba16Unorm", .rgba16Unorm),
            ("rgba16Float", .rgba16Float),
            ("rgba32Uint", .rgba32Uint),
            ("rgba32Float", .rgba32Float),
            ("depth16Unorm", .depth16Unorm),
            ("depth32Float", .depth32Float),
            ("stencil8", .stencil8),
            ("depth32Float_stencil8", .depth32Float_stencil8),
            ("astc_4x4_srgb", .astc_4x4_srgb),
            ("astc_4x4_ldr", .astc_4x4_ldr),
            ("astc_8x8_srgb", .astc_8x8_srgb),
            ("astc_8x8_ldr", .astc_8x8_ldr),
            ("eac_r11Unorm", .eac_r11Unorm),
            ("eac_rg11Unorm", .eac_rg11Unorm),
            ("etc2_rgb8", .etc2_rgb8),
            ("etc2_rgb8_srgb", .etc2_rgb8_srgb),
            ("etc2_rgb8a1", .etc2_rgb8a1),
            ("eac_rgba8", .eac_rgba8),
        ]

        // BC1-BC7 pixel formats require tvOS 16.4 or newer.
        if #available(tvOS 16.4, *) {
            formats += [
                ("bc1_rgba", .bc1_rgba),
                ("bc2_rgba", .bc2_rgba),
                ("bc3_rgba", .bc3_rgba),
                ("bc4_rUnorm", .bc4_rUnorm),
                ("bc5_rgUnorm", .bc5_rgUnorm),
                ("bc6H_rgbFloat", .bc6H_rgbFloat),
                ("bc7_rgbaUnorm", .bc7_rgbaUnorm),
            ]
        }

        var supported: [String] = []
        var unsupported: [String] = []

        for (label, format) in formats {
            // Try creating a texture descriptor
            let desc = MTLTextureDescriptor.texture2DDescriptor(
                pixelFormat: format,
                width: 4,
                height: 4,
                mipmapped: false
            )
            desc.usage = [.shaderRead]

            let tex = device.makeTexture(descriptor: desc)
            if tex != nil {
                supported.append(label)
            } else {
                unsupported.append(label)
            }
        }

        engine.report(module: name, key: "pixelFormats.supported_count", value: supported.count)
        engine.report(module: name, key: "pixelFormats.unsupported_count", value: unsupported.count)
        engine.report(module: name, key: "pixelFormats.supported", value: supported)
        engine.report(module: name, key: "pixelFormats.unsupported", value: unsupported)
    }

    private func probeWorkingSets(device: MTLDevice, engine: ReconEngine) {
        engine.report(module: name, key: "workingSet.recommended",
                      value: device.recommendedMaxWorkingSetSize)
        engine.report(module: name, key: "workingSet.currentAllocated",
                      value: device.currentAllocatedSize)
        // workingSet.maxTransferRate is unavailable: the tvOS SDK's MTLDevice
        // has no maxTransferRate member, so it is not reported.
    }

    private func probeComputePipeline(device: MTLDevice, engine: ReconEngine) {
        // Simple compute kernel — just enough to verify GPU access
        let source = """
        #include <metal_stdlib>
        using namespace metal;
        kernel void test_kernel(device uint *out [[buffer(0)]],
                                uint tid [[thread_position_in_grid]]) {
            out[tid] = tid * 2;
        }
        """

        do {
            let library = try device.makeLibrary(source: source, options: nil)
            engine.report(module: name, key: "compute.library", value: "created")

            guard let function = library.makeFunction(name: "test_kernel") else {
                engine.reportError(module: name, key: "compute.function", error: "makeFunction returned nil")
                return
            }
            engine.report(module: name, key: "compute.function", value: "created")

            let pipeline = try device.makeComputePipelineState(function: function)
            engine.report(module: name, key: "compute.pipeline", value: [
                "maxTotalThreadsPerThreadgroup": pipeline.maxTotalThreadsPerThreadgroup,
                "threadExecutionWidth": pipeline.threadExecutionWidth,
                "staticThreadgroupMemoryLength": pipeline.staticThreadgroupMemoryLength
            ])

            // Try executing
            guard let commandQueue = device.makeCommandQueue(),
                  let commandBuffer = commandQueue.makeCommandBuffer(),
                  let encoder = commandBuffer.makeComputeCommandEncoder() else {
                engine.reportError(module: name, key: "compute.exec", error: "failed to create command objects")
                return
            }

            let bufferSize = 256 * MemoryLayout<UInt32>.size
            guard let outBuffer = device.makeBuffer(length: bufferSize, options: .storageModeShared) else {
                encoder.endEncoding()
                engine.reportError(module: name, key: "compute.exec", error: "failed to create buffer")
                return
            }

            encoder.setComputePipelineState(pipeline)
            encoder.setBuffer(outBuffer, offset: 0, index: 0)
            encoder.dispatchThreads(MTLSize(width: 256, height: 1, depth: 1),
                                    threadsPerThreadgroup: MTLSize(width: 64, height: 1, depth: 1))
            encoder.endEncoding()
            commandBuffer.commit()
            commandBuffer.waitUntilCompleted()

            if commandBuffer.status == .completed {
                let ptr = outBuffer.contents().bindMemory(to: UInt32.self, capacity: 256)
                let sample = (0..<4).map { ptr[$0] }
                engine.report(module: name, key: "compute.exec", value: "success sample=\(sample)")
            } else {
                engine.reportError(module: name, key: "compute.exec",
                                   error: "status=\(commandBuffer.status.rawValue) error=\(commandBuffer.error?.localizedDescription ?? "nil")")
            }
        } catch {
            engine.reportError(module: name, key: "compute", error: error.localizedDescription)
        }
    }

    private func probeShaderVersions(device: MTLDevice, engine: ReconEngine) {
        // Metal Shading Language versions
        let versions: [(String, MTLLanguageVersion)] = [
            ("1.0", .version1_0),
            ("1.1", .version1_1),
            ("1.2", .version1_2),
            ("2.0", .version2_0),
            ("2.1", .version2_1),
            ("2.2", .version2_2),
            ("2.3", .version2_3),
            ("2.4", .version2_4),
        ]

        var supportedVersions: [String] = []
        for (label, version) in versions {
            let options = MTLCompileOptions()
            options.languageVersion = version

            let trivialSource = """
            #include <metal_stdlib>
            using namespace metal;
            kernel void noop() {}
            """

            do {
                let _ = try device.makeLibrary(source: trivialSource, options: options)
                supportedVersions.append(label)
            } catch {
                // Not supported
            }
        }

        // Try 3.0 if available at compile time
        if #available(tvOS 16.0, *) {
            let options = MTLCompileOptions()
            options.languageVersion = .version3_0
            do {
                let _ = try device.makeLibrary(source: """
                #include <metal_stdlib>
                using namespace metal;
                kernel void noop() {}
                """, options: options)
                supportedVersions.append("3.0")
            } catch {}
        }

        if #available(tvOS 17.0, *) {
            let options = MTLCompileOptions()
            options.languageVersion = .version3_1
            do {
                let _ = try device.makeLibrary(source: """
                #include <metal_stdlib>
                using namespace metal;
                kernel void noop() {}
                """, options: options)
                supportedVersions.append("3.1")
            } catch {}
        }

        engine.report(module: name, key: "shaderVersions", value: supportedVersions)
    }

    private func probeIndirectCommandBuffers(device: MTLDevice, engine: ReconEngine) {
        let icbDesc = MTLIndirectCommandBufferDescriptor()
        icbDesc.commandTypes = [.draw, .drawIndexed]
        icbDesc.inheritBuffers = false
        icbDesc.inheritPipelineState = false
        icbDesc.maxVertexBufferBindCount = 10
        icbDesc.maxFragmentBufferBindCount = 10

        let icb = device.makeIndirectCommandBuffer(descriptor: icbDesc, maxCommandCount: 100, options: [])
        engine.report(module: name, key: "indirectCommandBuffer", value: icb != nil ? "supported" : "not_supported")

        // Compute ICB
        let computeIcbDesc = MTLIndirectCommandBufferDescriptor()
        computeIcbDesc.commandTypes = [.concurrentDispatch]
        computeIcbDesc.inheritBuffers = false
        computeIcbDesc.inheritPipelineState = false
        computeIcbDesc.maxKernelBufferBindCount = 10

        let computeIcb = device.makeIndirectCommandBuffer(descriptor: computeIcbDesc, maxCommandCount: 100, options: [])
        engine.report(module: name, key: "indirectCommandBuffer.compute", value: computeIcb != nil ? "supported" : "not_supported")
    }

    private func probeAdditionalFeatures(device: MTLDevice, engine: ReconEngine) {
        // Sparse textures
        if #available(tvOS 16.0, *) {
            engine.report(module: name, key: "feature.sparseTileSize", value: device.sparseTileSizeInBytes)
        }

        // Counters
        engine.report(module: name, key: "feature.counterSamplingPoints",
                      value: "checking...")

        if #available(tvOS 16.0, *) {
            let counterSets = device.counterSets ?? []
            engine.report(module: name, key: "feature.counterSets.count", value: counterSets.count)
            for cs in counterSets {
                let counters = cs.counters.map { $0.name }
                engine.report(module: name, key: "feature.counterSet.\(cs.name)", value: counters)
            }
        }

        // Heap
        let heapDesc = MTLHeapDescriptor()
        heapDesc.size = 1024 * 1024  // 1MB
        heapDesc.storageMode = .shared
        let heap = device.makeHeap(descriptor: heapDesc)
        engine.report(module: name, key: "feature.heap", value: heap != nil ? "supported" : "not_supported")
        if let heap = heap {
            engine.report(module: name, key: "feature.heap.currentAllocatedSize",
                          value: heap.currentAllocatedSize)
            engine.report(module: name, key: "feature.heap.maxAvailableSize",
                          value: heap.maxAvailableSize(alignment: 256))
        }

        // Shared events
        let event = device.makeSharedEvent()
        engine.report(module: name, key: "feature.sharedEvent", value: event != nil ? "supported" : "not_supported")

        // Sample count support
        for sampleCount in [1, 2, 4, 8, 16] {
            let supported = device.supportsTextureSampleCount(sampleCount)
            engine.report(module: name, key: "feature.sampleCount.\(sampleCount)", value: supported)
        }
    }
    #endif
}
