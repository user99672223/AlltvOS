// MemoryLayoutMapperModule.swift
// Walks the process virtual address space using vm_region_recurse_64 to map every
// memory region. Records protection, sharing, page stats, and VM tags. Tests kernel
// address reads, vm_allocate, vm_protect, and records ASLR slides and layout stats.

import Foundation

final class MemoryLayoutMapperModule: ReconModule {
    let name = "MemoryLayoutMapper"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        walkVirtualMemory(engine: engine)
        probeKernelAddresses(engine: engine)
        testVmAllocate(engine: engine)
        testVmProtect(engine: engine)
        recordASLRInfo(engine: engine)
    }

    // MARK: - VM Region Walk

    private func walkVirtualMemory(engine: ReconEngine) {
        let task = mach_task_self_
        var address: vm_address_t = 0
        var regionCount = 0
        var totalSize: UInt64 = 0
        var regionSummary: [String: Int] = [:]
        var regions: [[String: Any]] = []

        while true {
            var size: vm_size_t = 0
            var info = vm_region_submap_info_64()
            var infoCount = mach_msg_type_number_t(MemoryLayout<vm_region_submap_info_64>.size / MemoryLayout<Int32>.size)
            var depth: UInt32 = 1024

            let kr = withUnsafeMutablePointer(to: &info) { infoPtr -> kern_return_t in
                infoPtr.withMemoryRebound(to: Int32.self, capacity: Int(infoCount)) { rawPtr -> kern_return_t in
                    return vm_region_recurse_64(
                        task,
                        &address,
                        &size,
                        &depth,
                        rawPtr,
                        &infoCount
                    )
                }
            }

            guard kr == KERN_SUCCESS else {
                break
            }

            regionCount += 1
            totalSize += size

            let tag = vmTagName(Int(info.user_tag))
            regionSummary[tag, default: 0] += 1

            // Log first 500 regions in detail, then only count
            if regionCount <= 500 {
                var entry: [String: Any] = [
                    "address": String(format: "0x%016llx", address),
                    "size": size,
                    "size_human": humanSize(size),
                    "protection": protectionString(info.protection),
                    "max_protection": protectionString(info.max_protection),
                    "inheritance": inheritanceName(info.inheritance),
                    "share_mode": shareModeName(info.share_mode),
                    "depth": depth,
                    "pages_resident": info.pages_resident,
                    "pages_shared_now_private": info.pages_shared_now_private,
                    "pages_swapped_out": info.pages_swapped_out,
                    "pages_dirtied": info.pages_dirtied,
                    "pages_reusable": info.pages_reusable,
                    "external_pager": info.external_pager,
                    "shadow_depth": info.shadow_depth,
                    "user_tag": info.user_tag,
                    "tag_name": tag,
                    "is_submap": info.is_submap
                ]

                // Identify region purpose heuristically
                if info.user_tag == 1 { entry["purpose"] = "malloc" }
                else if info.user_tag == 30 { entry["purpose"] = "stack" }
                else if info.user_tag == 33 { entry["purpose"] = "dyld" }
                else if info.user_tag == 35 { entry["purpose"] = "dyld_shared_cache" }
                else if info.user_tag == 42 { entry["purpose"] = "CoreServices" }

                regions.append(entry)
            }

            // Report in batches
            if regions.count >= 100 {
                engine.report(module: name, key: "vm_regions_batch", value: regions)
                regions.removeAll()
            }

            // Advance past this region
            address += vm_address_t(size)
            if address == 0 { break } // wrapped around
        }

        // Flush remaining
        if !regions.isEmpty {
            engine.report(module: name, key: "vm_regions_batch", value: regions)
        }

        engine.report(module: name, key: "vm_region_summary", value: [
            "total_regions": regionCount,
            "total_mapped_size": totalSize,
            "total_mapped_human": humanSize(totalSize),
            "tag_distribution": regionSummary
        ] as [String: Any])
    }

    // MARK: - Kernel Address Probes

    private func probeKernelAddresses(engine: ReconEngine) {
        let task = mach_task_self_
        let testAddresses: [UInt64] = [
            0xfffffff000000000,
            0xfffffff007004000,
            0xfffffff00700c000,
            0xfffffffe00000000,
            0xffffff8000000000
        ]

        for addr in testAddresses {
            var data: vm_offset_t = 0
            var dataCnt: mach_msg_type_number_t = 0

            let kr = vm_read(
                task,
                vm_address_t(addr),
                vm_size_t(getpagesize()),
                &data,
                &dataCnt
            )

            var result: [String: Any] = [
                "address": String(format: "0x%016llx", addr),
                "kern_return": kr
            ]

            switch kr {
            case KERN_SUCCESS:
                result["status"] = "SUCCESS (unexpected!)"
                result["bytes_read"] = dataCnt
                vm_deallocate(task, data, vm_size_t(dataCnt))
            case KERN_INVALID_ADDRESS:
                result["status"] = "KERN_INVALID_ADDRESS"
            case KERN_PROTECTION_FAILURE:
                result["status"] = "KERN_PROTECTION_FAILURE"
            case 1: // KERN_INVALID_ARGUMENT
                result["status"] = "KERN_INVALID_ARGUMENT"
            default:
                result["status"] = "KERN_ERROR_\(kr)"
            }

            engine.report(module: name, key: "kernel_address_read", value: result)
        }
    }

    // MARK: - vm_allocate

    private func testVmAllocate(engine: ReconEngine) {
        let task = mach_task_self_
        let pageSize = vm_size_t(getpagesize())

        // VM_FLAGS_ANYWHERE
        do {
            var addr: vm_address_t = 0
            let kr = vm_allocate(task, &addr, pageSize, VM_FLAGS_ANYWHERE)
            engine.report(module: name, key: "vm_allocate_anywhere", value: [
                "success": kr == KERN_SUCCESS,
                "kern_return": kr,
                "address": kr == KERN_SUCCESS ? String(format: "0x%lx", addr) : "n/a"
            ] as [String: Any])
            if kr == KERN_SUCCESS {
                vm_deallocate(task, addr, pageSize)
            }
        }

        // VM_FLAGS_FIXED at a specific address
        do {
            // First allocate anywhere to get a valid address, deallocate, then try fixed
            var anyAddr: vm_address_t = 0
            let kr1 = vm_allocate(task, &anyAddr, pageSize, VM_FLAGS_ANYWHERE)
            if kr1 == KERN_SUCCESS {
                vm_deallocate(task, anyAddr, pageSize)

                var fixedAddr = anyAddr
                let kr2 = vm_allocate(task, &fixedAddr, pageSize, VM_FLAGS_FIXED)
                engine.report(module: name, key: "vm_allocate_fixed", value: [
                    "success": kr2 == KERN_SUCCESS,
                    "kern_return": kr2,
                    "requested_address": String(format: "0x%lx", anyAddr),
                    "actual_address": kr2 == KERN_SUCCESS ? String(format: "0x%lx", fixedAddr) : "n/a"
                ] as [String: Any])
                if kr2 == KERN_SUCCESS {
                    vm_deallocate(task, fixedAddr, pageSize)
                }
            }
        }
    }

    // MARK: - vm_protect

    private func testVmProtect(engine: ReconEngine) {
        let task = mach_task_self_
        let pageSize = vm_size_t(getpagesize())

        // Allocate RW page, try to add EXEC
        var addr: vm_address_t = 0
        let kr = vm_allocate(task, &addr, pageSize, VM_FLAGS_ANYWHERE)
        if kr == KERN_SUCCESS {
            // Set to RW first
            let kr1 = vm_protect(task, addr, pageSize, 0, VM_PROT_READ | VM_PROT_WRITE)
            engine.report(module: name, key: "vm_protect_rw", value: [
                "success": kr1 == KERN_SUCCESS, "kern_return": kr1
            ] as [String: Any])

            // Try to add EXEC
            let kr2 = vm_protect(task, addr, pageSize, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
            engine.report(module: name, key: "vm_protect_rwx", value: [
                "success": kr2 == KERN_SUCCESS,
                "kern_return": kr2,
                "note": kr2 == KERN_SUCCESS ? "can_add_exec_to_data" : "exec_protection_denied"
            ] as [String: Any])

            // Try max_protection change
            let kr3 = vm_protect(task, addr, pageSize, 1, VM_PROT_ALL)
            engine.report(module: name, key: "vm_protect_set_max", value: [
                "success": kr3 == KERN_SUCCESS, "kern_return": kr3
            ] as [String: Any])

            vm_deallocate(task, addr, pageSize)
        }
    }

    // MARK: - ASLR Info

    private func recordASLRInfo(engine: ReconEngine) {
        // Main binary ASLR slide
        if _dyld_image_count() > 0 {
            let slide = _dyld_get_image_vmaddr_slide(0)
            engine.report(module: name, key: "aslr_main_binary_slide", value: String(format: "0x%lx", slide))

            if let imageName = _dyld_get_image_name(0) {
                engine.report(module: name, key: "aslr_main_binary", value: String(cString: imageName))
            }
        }

        // Shared cache base - look for dyld_shared_cache region in our walk
        // Also try _dyld_get_shared_cache_range
        typealias SharedCacheRangeFunc = @convention(c) (UnsafeMutablePointer<Int>) -> UnsafeRawPointer?
        let handle = dlopen(nil, RTLD_NOW)
        if let fnPtr = dlsym(handle, "_dyld_get_shared_cache_range") {
            let fn = unsafeBitCast(fnPtr, to: SharedCacheRangeFunc.self)
            var cacheLen: Int = 0
            if let basePtr = fn(&cacheLen) {
                engine.report(module: name, key: "shared_cache", value: [
                    "base_address": String(format: "0x%lx", Int(bitPattern: basePtr)),
                    "size": cacheLen,
                    "size_human": humanSize(UInt64(cacheLen))
                ] as [String: Any])
            }
        }

        // _dyld_get_shared_cache_uuid
        typealias SharedCacheUUIDFunc = @convention(c) (UnsafeMutablePointer<uuid_t>) -> Bool
        if let fnPtr = dlsym(handle, "_dyld_get_shared_cache_uuid") {
            let fn = unsafeBitCast(fnPtr, to: SharedCacheUUIDFunc.self)
            var uuid = uuid_t(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
            if fn(&uuid) {
                let uuidStr = withUnsafePointer(to: uuid) { ptr -> String in
                    let raw = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
                    return (0..<16).map { String(format: "%02x", raw[$0]) }
                        .enumerated()
                        .map { idx, hex in [3,5,7,9].contains(idx) ? hex + "-" : hex }
                        .joined()
                }
                engine.report(module: name, key: "shared_cache_uuid", value: uuidStr)
            }
        }

        // Stack base address
        do {
            var stackAddr: UInt64 = 0
            withUnsafePointer(to: &stackAddr) { ptr in
                // The address of a stack variable approximates the stack location
                let approxStackBase = UInt(bitPattern: ptr)
                engine.report(module: name, key: "stack_approx_base", value: String(format: "0x%lx", approxStackBase))
            }
        }

        if handle != nil { dlclose(handle) }
    }

    // MARK: - Helpers

    private func protectionString(_ prot: vm_prot_t) -> String {
        var s = ""
        s += (prot & VM_PROT_READ) != 0 ? "r" : "-"
        s += (prot & VM_PROT_WRITE) != 0 ? "w" : "-"
        s += (prot & VM_PROT_EXECUTE) != 0 ? "x" : "-"
        return s
    }

    private func inheritanceName(_ inh: vm_inherit_t) -> String {
        switch inh {
        case VM_INHERIT_SHARE: return "share"
        case VM_INHERIT_COPY: return "copy"
        case VM_INHERIT_NONE: return "none"
        default: return "inherit_\(inh)"
        }
    }

    private func shareModeName(_ mode: UInt8) -> String {
        switch mode {
        case 1: return "COW"
        case 2: return "PRIVATE"
        case 3: return "EMPTY"
        case 4: return "SHARED"
        case 5: return "TRUESHARED"
        case 6: return "PRIVATE_ALIASED"
        case 7: return "SHARED_ALIASED"
        case 8: return "LARGE_PAGE"
        default: return "mode_\(mode)"
        }
    }

    private func vmTagName(_ tag: Int) -> String {
        let knownTags: [Int: String] = [
            0: "VM_MEMORY_NONE",
            1: "VM_MEMORY_MALLOC",
            2: "VM_MEMORY_MALLOC_SMALL",
            3: "VM_MEMORY_MALLOC_LARGE",
            4: "VM_MEMORY_MALLOC_HUGE",
            5: "VM_MEMORY_SBRK",
            6: "VM_MEMORY_REALLOC",
            7: "VM_MEMORY_MALLOC_TINY",
            8: "VM_MEMORY_MALLOC_LARGE_REUSABLE",
            9: "VM_MEMORY_MALLOC_LARGE_REUSED",
            10: "VM_MEMORY_ANALYSIS_TOOL",
            11: "VM_MEMORY_MALLOC_NANO",
            20: "VM_MEMORY_MACH_MSG",
            21: "VM_MEMORY_IOKIT",
            30: "VM_MEMORY_STACK",
            31: "VM_MEMORY_GUARD",
            32: "VM_MEMORY_SHARED_PMAP",
            33: "VM_MEMORY_DYLIB",
            34: "VM_MEMORY_OBJC_DISPATCHERS",
            35: "VM_MEMORY_UNSHARED_PMAP",
            40: "VM_MEMORY_APPKIT",
            41: "VM_MEMORY_FOUNDATION",
            42: "VM_MEMORY_COREGRAPHICS",
            43: "VM_MEMORY_CORESERVICES",
            44: "VM_MEMORY_CARBON",
            45: "VM_MEMORY_JAVA",
            46: "VM_MEMORY_COREDATA",
            47: "VM_MEMORY_COREDATA_OBJECTIDS",
            50: "VM_MEMORY_ATS",
            51: "VM_MEMORY_LAYERKIT",
            52: "VM_MEMORY_CGIMAGE",
            53: "VM_MEMORY_TCMALLOC",
            54: "VM_MEMORY_COREGRAPHICS_DATA",
            55: "VM_MEMORY_COREGRAPHICS_SHARED",
            56: "VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS",
            57: "VM_MEMORY_COREGRAPHICS_BACKINGSTORES",
            58: "VM_MEMORY_COREGRAPHICS_XALLOC",
            60: "VM_MEMORY_DYLD",
            61: "VM_MEMORY_DYLD_MALLOC",
            62: "VM_MEMORY_SQLITE",
            63: "VM_MEMORY_JAVASCRIPT_CORE",
            64: "VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR",
            65: "VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE",
            66: "VM_MEMORY_GLSL",
            67: "VM_MEMORY_OPENCL",
            68: "VM_MEMORY_COREIMAGE",
            69: "VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS",
            70: "VM_MEMORY_IMAGEIO",
            71: "VM_MEMORY_COREPROFILE",
            72: "VM_MEMORY_ASSETSD",
            73: "VM_MEMORY_OS_ALLOC_ONCE",
            74: "VM_MEMORY_LIBDISPATCH",
            75: "VM_MEMORY_ACCELERATE",
            76: "VM_MEMORY_COREUI",
            77: "VM_MEMORY_COREUIFILE",
            78: "VM_MEMORY_GENEALOGY",
            79: "VM_MEMORY_RAWCAMERA",
            80: "VM_MEMORY_CORPSEINFO",
            81: "VM_MEMORY_ASL",
            82: "VM_MEMORY_SWIFT_RUNTIME",
            83: "VM_MEMORY_SWIFT_METADATA",
            84: "VM_MEMORY_DHMM",
            85: "VM_MEMORY_SCENEKIT",
            86: "VM_MEMORY_SKYWALK",
            87: "VM_MEMORY_IOSURFACE",
            88: "VM_MEMORY_LIBNETWORK",
            89: "VM_MEMORY_AUDIO",
            90: "VM_MEMORY_VIDEOBITSTREAM",
            91: "VM_MEMORY_CM_XPC",
            92: "VM_MEMORY_CM_RPC",
            93: "VM_MEMORY_CM_MEMORYPOOL",
            94: "VM_MEMORY_CM_READCACHE",
            95: "VM_MEMORY_CM_CRABS",
            96: "VM_MEMORY_QUICKLOOK_THUMBNAILS",
            97: "VM_MEMORY_ACCOUNTS",
            98: "VM_MEMORY_SANITIZER",
            99: "VM_MEMORY_IOACCELERATOR",
            100: "VM_MEMORY_CM_REGWARP",
            255: "VM_MEMORY_APPLICATION_SPECIFIC_16"
        ]
        return knownTags[tag] ?? "VM_TAG_\(tag)"
    }

    private func humanSize(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        let kb = Double(bytes) / 1024.0
        if kb < 1024 { return String(format: "%.1f KB", kb) }
        let mb = kb / 1024.0
        if mb < 1024 { return String(format: "%.1f MB", mb) }
        let gb = mb / 1024.0
        return String(format: "%.2f GB", gb)
    }
}
