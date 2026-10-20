// CompilerAndRuntimeInfoModule: Reports Swift/ObjC runtime versions, JIT capability,
// dyld shared cache info, and compile-time target conditionals.

import Foundation
#if canImport(MachO)
import MachO
#endif

final class CompilerAndRuntimeInfoModule: ReconModule {
    let name = "CompilerAndRuntimeInfo"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeSwiftVersion(engine: engine)
        probeObjCRuntime(engine: engine)
        probeJITCapability(engine: engine)
        probeDyldInfo(engine: engine)
        probeTargetConditionals(engine: engine)
        probeLibraryVersions(engine: engine)
        probeAppleArray(engine: engine)
    }

    private func probeSwiftVersion(engine: ReconEngine) {
        // Compile-time Swift version checks
        #if swift(>=6.0)
        engine.report(module: name, key: "swift_version_gte", value: "6.0")
        #elseif swift(>=5.10)
        engine.report(module: name, key: "swift_version_gte", value: "5.10")
        #elseif swift(>=5.9)
        engine.report(module: name, key: "swift_version_gte", value: "5.9")
        #elseif swift(>=5.8)
        engine.report(module: name, key: "swift_version_gte", value: "5.8")
        #elseif swift(>=5.7)
        engine.report(module: name, key: "swift_version_gte", value: "5.7")
        #else
        engine.report(module: name, key: "swift_version_gte", value: "<5.7")
        #endif

        // Try dlsym for runtime version
        if let handle = dlopen(nil, RTLD_LAZY) {
            if let sym = dlsym(handle, "swift_getObjectType") {
                engine.report(module: name, key: "swift_runtime_swift_getObjectType", value: String(format: "0x%lx", UInt(bitPattern: sym)))
            }
            if let sym = dlsym(handle, "_swift_stdlib_reportFatalError") {
                engine.report(module: name, key: "swift_stdlib_symbol", value: String(format: "0x%lx", UInt(bitPattern: sym)))
            }
            dlclose(handle)
        }

        // ABI stability
        #if swift(>=5.0)
        engine.report(module: name, key: "swift_abi_stable", value: "true")
        #else
        engine.report(module: name, key: "swift_abi_stable", value: "false")
        #endif
    }

    private func probeObjCRuntime(engine: ReconEngine) {
        // ObjC runtime info via class counting
        var classCount: UInt32 = 0
        if let imageName = class_getImageName(NSObject.self),
           let classList = objc_copyClassNamesForImage(imageName, &classCount) {
            engine.report(module: name, key: "objc_classes_in_foundation", value: "\(classCount)")
            free(UnsafeMutableRawPointer(mutating: classList))
        }

        // Total class count
        let totalCount = objc_getClassList(nil, 0)
        engine.report(module: name, key: "objc_total_class_count", value: "\(totalCount)")

        // Protocol count
        var protoCount: UInt32 = 0
        if let protos = objc_copyProtocolList(&protoCount) {
            engine.report(module: name, key: "objc_total_protocol_count", value: "\(protoCount)")
            free(UnsafeMutableRawPointer(mutating: protos))
        }
    }

    private func probeJITCapability(engine: ReconEngine) {
        // Try MAP_JIT
        let mapJitFlag: Int32 = 0x0800 // MAP_JIT
        let pageSize = Int(getpagesize())
        let addr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | mapJitFlag, -1, 0)
        if addr == MAP_FAILED {
            engine.report(module: name, key: "mmap_MAP_JIT", value: "denied, errno=\(errno) (\(String(cString: strerror(errno))))")
        } else {
            engine.report(module: name, key: "mmap_MAP_JIT", value: "allowed")
            munmap(addr, pageSize)
        }

        // Try mmap PROT_EXEC
        let execAddr = mmap(nil, pageSize, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0)
        if execAddr == MAP_FAILED {
            engine.report(module: name, key: "mmap_PROT_EXEC", value: "denied, errno=\(errno) (\(String(cString: strerror(errno))))")
        } else {
            engine.report(module: name, key: "mmap_PROT_EXEC", value: "allowed")
            munmap(execAddr, pageSize)
        }

        // Try pthread_jit_write_protect_np
        if let handle = dlopen(nil, RTLD_LAZY) {
            if let sym = dlsym(handle, "pthread_jit_write_protect_np") {
                engine.report(module: name, key: "pthread_jit_write_protect_np", value: "available at \(String(format: "0x%lx", UInt(bitPattern: sym)))")
                typealias JitProtectFunc = @convention(c) (Bool) -> Void
                let fn = unsafeBitCast(sym, to: JitProtectFunc.self)
                fn(true)
                fn(false)
                engine.report(module: name, key: "pthread_jit_write_protect_np_call", value: "no_crash")
            } else {
                engine.report(module: name, key: "pthread_jit_write_protect_np", value: "not_found")
            }

            if let sym = dlsym(handle, "pthread_jit_write_protect_supported_np") {
                typealias JitSupportedFunc = @convention(c) () -> Int32
                let fn = unsafeBitCast(sym, to: JitSupportedFunc.self)
                let supported = fn()
                engine.report(module: name, key: "pthread_jit_write_protect_supported_np", value: "\(supported)")
            }
            dlclose(handle)
        }
    }

    private func probeDyldInfo(engine: ReconEngine) {
        // dyld image count and shared cache info
        let imageCount = _dyld_image_count()
        engine.report(module: name, key: "dyld_image_count", value: "\(imageCount)")

        // Main executable slide
        if imageCount > 0 {
            let slide = _dyld_get_image_vmaddr_slide(0)
            engine.report(module: name, key: "main_executable_slide", value: String(format: "0x%lx", slide))
            if let imageName = _dyld_get_image_name(0) {
                engine.report(module: name, key: "main_executable_path", value: String(cString: imageName))
            }
        }

        // Shared cache UUID - find dyld image and extract
        for i in 0..<imageCount {
            if let imagePath = _dyld_get_image_name(i) {
                let nameStr = String(cString: imagePath)
                if nameStr.contains("libdyld") || nameStr.contains("dyld_sim") {
                    engine.report(module: name, key: "dyld_library_path", value: nameStr)
                    break
                }
            }
        }

        // Try _dyld_get_shared_cache_uuid if available
        if let handle = dlopen(nil, RTLD_LAZY) {
            if let sym = dlsym(handle, "_dyld_get_shared_cache_uuid") {
                typealias SharedCacheUUIDFunc = @convention(c) (UnsafeMutableRawPointer) -> Bool
                let fn = unsafeBitCast(sym, to: SharedCacheUUIDFunc.self)
                var uuid = uuid_t(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
                let result = fn(&uuid)
                if result {
                    let uuidBytes = withUnsafePointer(to: &uuid) { ptr -> [UInt8] in
                        let raw = UnsafeRawPointer(ptr)
                        return (0..<16).map { raw.load(fromByteOffset: $0, as: UInt8.self) }
                    }
                    let uuidStr = uuidBytes.map { String(format: "%02X", $0) }.joined()
                    engine.report(module: self.name, key: "shared_cache_uuid", value: uuidStr)
                } else {
                    engine.report(module: self.name, key: "shared_cache_uuid", value: "unavailable")
                }
            }

            if let sym = dlsym(handle, "_dyld_shared_cache_file_path") {
                typealias CachePathFunc = @convention(c) () -> UnsafePointer<CChar>?
                let fn = unsafeBitCast(sym, to: CachePathFunc.self)
                if let path = fn() {
                    engine.report(module: self.name, key: "shared_cache_path", value: String(cString: path))
                }
            }
            dlclose(handle)
        }
    }

    private func probeTargetConditionals(engine: ReconEngine) {
        #if targetEnvironment(simulator)
        engine.report(module: name, key: "TARGET_OS_SIMULATOR", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_SIMULATOR", value: "false")
        #endif

        #if os(tvOS)
        engine.report(module: name, key: "TARGET_OS_TV", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_TV", value: "false")
        #endif

        #if os(iOS)
        engine.report(module: name, key: "TARGET_OS_IOS", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_IOS", value: "false")
        #endif

        #if os(macOS)
        engine.report(module: name, key: "TARGET_OS_OSX", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_OSX", value: "false")
        #endif

        #if os(watchOS)
        engine.report(module: name, key: "TARGET_OS_WATCH", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_WATCH", value: "false")
        #endif

        #if targetEnvironment(macCatalyst)
        engine.report(module: name, key: "TARGET_OS_MACCATALYST", value: "true")
        #else
        engine.report(module: name, key: "TARGET_OS_MACCATALYST", value: "false")
        #endif

        #if arch(arm64)
        engine.report(module: name, key: "arch", value: "arm64")
        #elseif arch(x86_64)
        engine.report(module: name, key: "arch", value: "x86_64")
        #else
        engine.report(module: name, key: "arch", value: "other")
        #endif

        #if DEBUG
        engine.report(module: name, key: "DEBUG", value: "true")
        #else
        engine.report(module: name, key: "DEBUG", value: "false")
        #endif

        #if canImport(UIKit)
        engine.report(module: name, key: "canImport_UIKit", value: "true")
        #endif
        #if canImport(IOKit)
        engine.report(module: name, key: "canImport_IOKit", value: "true")
        #endif
        #if canImport(Metal)
        engine.report(module: name, key: "canImport_Metal", value: "true")
        #endif
        #if canImport(CryptoKit)
        engine.report(module: name, key: "canImport_CryptoKit", value: "true")
        #endif
        #if canImport(OSLog)
        engine.report(module: name, key: "canImport_OSLog", value: "true")
        #endif
    }

    private func probeLibraryVersions(engine: ReconEngine) {
        if let handle = dlopen(nil, RTLD_LAZY) {
            // libsystem version
            let libsystemSymbols = [
                "libsystem_kernel_version",
                "libsystem_platform_version",
                "__crashreporter_info__"
            ]
            for sym in libsystemSymbols {
                if let addr = dlsym(handle, sym) {
                    engine.report(module: name, key: "symbol_\(sym)", value: String(format: "0x%lx", UInt(bitPattern: addr)))
                }
            }

            // dispatch version
            if let sym = dlsym(handle, "_dispatch_introspection_hook_queue_create") {
                engine.report(module: name, key: "libdispatch_introspection", value: "available")
            }

            // Mach-O info for libSystem
            if let sym = dlsym(handle, "mach_msg") {
                var info = Dl_info()
                if dladdr(sym, &info) != 0 {
                    if let fname = info.dli_fname {
                        engine.report(module: name, key: "libsystem_path", value: String(cString: fname))
                    }
                    if let sname = info.dli_sname {
                        engine.report(module: name, key: "mach_msg_symbol", value: String(cString: sname))
                    }
                }
            }

            dlclose(handle)
        }

        // Report pointer size and endianness
        engine.report(module: name, key: "pointer_size", value: "\(MemoryLayout<UnsafeRawPointer>.size)")
        engine.report(module: name, key: "int_size", value: "\(MemoryLayout<Int>.size)")

        let endian: String
        #if _endian(big)
        endian = "big"
        #else
        endian = "little"
        #endif
        engine.report(module: name, key: "endianness", value: endian)
    }

    private func probeAppleArray(engine: ReconEngine) {
        guard let handle = dlopen(nil, RTLD_LAZY) else { return }
        defer { dlclose(handle) }

        // Executable path via _NSGetExecutablePath
        if let sym = dlsym(handle, "_NSGetExecutablePath") {
            typealias ExePathFn = @convention(c) (UnsafeMutablePointer<CChar>, UnsafeMutablePointer<UInt32>) -> Int32
            let fn = unsafeBitCast(sym, to: ExePathFn.self)
            var size: UInt32 = 1024
            var buf = [CChar](repeating: 0, count: Int(size))
            if fn(&buf, &size) == 0 {
                engine.report(module: name, key: "executable_path", value: String(cString: buf))
            }
        }

        // Process arguments
        let args = ProcessInfo.processInfo.arguments
        engine.report(module: name, key: "process_argument_count", value: "\(args.count)")
        for (i, arg) in args.enumerated() {
            engine.report(module: name, key: "process_arg_\(i)", value: arg)
        }

        // Walk past argv and envp to find the "apple" array
        if let argcSym = dlsym(handle, "_NSGetArgc"),
           let argvSym = dlsym(handle, "_NSGetArgv") {
            typealias ArgcFn = @convention(c) () -> UnsafeMutablePointer<Int32>
            typealias ArgvFn = @convention(c) () -> UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>>
            let getArgc = unsafeBitCast(argcSym, to: ArgcFn.self)
            let getArgv = unsafeBitCast(argvSym, to: ArgvFn.self)
            let argc = getArgc().pointee
            let argv = getArgv().pointee
            engine.report(module: name, key: "raw_argc", value: "\(argc)")

            var idx = Int(argc) + 1
            while argv[idx] != nil { idx += 1 }
            idx += 1
            var appleIdx = 0
            while let ptr = argv[idx] {
                engine.report(module: name, key: "apple_array_\(appleIdx)", value: String(cString: ptr))
                appleIdx += 1
                idx += 1
                if appleIdx > 50 { break }
            }
            engine.report(module: name, key: "apple_array_count", value: "\(appleIdx)")
        }

        // Shared cache range
        if let sym = dlsym(handle, "_dyld_get_shared_cache_range") {
            typealias RangeFn = @convention(c) (UnsafeMutablePointer<Int>) -> UnsafeRawPointer?
            let fn = unsafeBitCast(sym, to: RangeFn.self)
            var length: Int = 0
            if let basePtr = fn(&length) {
                engine.report(module: name, key: "shared_cache_base", value: String(format: "0x%lx", UInt(bitPattern: basePtr)))
                engine.report(module: name, key: "shared_cache_length_mb", value: "\(length / (1024 * 1024))")
            }
        }

        // SDK and min OS versions
        if let sym = dlsym(handle, "dyld_get_program_sdk_version") {
            typealias SDKFn = @convention(c) () -> UInt32
            let fn = unsafeBitCast(sym, to: SDKFn.self)
            let sdk = fn()
            engine.report(module: name, key: "program_sdk_version", value: "\((sdk >> 16) & 0xFFFF).\((sdk >> 8) & 0xFF).\(sdk & 0xFF)")
        }
        if let sym = dlsym(handle, "dyld_get_min_os_version") {
            typealias MinOSFn = @convention(c) () -> UInt32
            let fn = unsafeBitCast(sym, to: MinOSFn.self)
            let v = fn()
            engine.report(module: name, key: "min_os_version", value: "\((v >> 16) & 0xFFFF).\((v >> 8) & 0xFF).\(v & 0xFF)")
        }

        // Word size
        engine.report(module: name, key: "word_size_bits", value: "\(MemoryLayout<Int>.size * 8)")
    }
}
