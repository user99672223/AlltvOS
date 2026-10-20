// DyldCacheInspectorModule.swift
// Enumerates all loaded dyld images, parses Mach-O headers and load
// commands, probes private frameworks via dlopen/dlsym, and attempts
// GestaltAnswer queries via MGCopyAnswer.
// Reveals the full set of libraries mapped into the process, ASLR
// layout, and which private symbols are reachable from the sandbox.

import Foundation
import MachO

final class DyldCacheInspectorModule: ReconModule {
    let name = "DyldCacheInspector"
    let timeout: TimeInterval = 120

    func run(engine: ReconEngine) {
        enumerateLoadedImages(engine: engine)
        probePrivateFrameworks(engine: engine)
        recordASLRInfo(engine: engine)
    }

    // MARK: - Loaded images

    private func enumerateLoadedImages(engine: ReconEngine) {
        let count = _dyld_image_count()
        engine.report(module: name, key: "image_count", value: count)

        for i in 0..<count {
            guard let namePtr = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: namePtr)
            let slide = _dyld_get_image_vmaddr_slide(i)
            guard let headerPtr = _dyld_get_image_header(i) else {
                engine.report(module: name, key: "image.\(i)", value: ["name": imageName, "slide": String(format: "0x%llx", slide)])
                continue
            }

            var imageInfo: [String: Any] = [
                "name": imageName,
                "index": i,
                "slide": String(format: "0x%llx", slide),
                "loadAddress": String(format: "0x%llx", UInt(bitPattern: headerPtr)),
            ]

            // Parse mach_header_64
            let header = headerPtr.pointee
            imageInfo["magic"] = String(format: "0x%08x", header.magic)
            imageInfo["cputype"] = header.cputype
            imageInfo["cpusubtype"] = header.cpusubtype
            imageInfo["filetype"] = header.filetype
            imageInfo["ncmds"] = header.ncmds
            imageInfo["sizeofcmds"] = header.sizeofcmds
            imageInfo["flags"] = String(format: "0x%08x", header.flags)

            // Parse load commands
            if header.magic == MH_MAGIC_64 {
                let header64Ptr = UnsafeRawPointer(headerPtr).assumingMemoryBound(to: mach_header_64.self)
                let loadCommands = parseLoadCommands(header: header64Ptr, ncmds: header.ncmds, sizeofcmds: header.sizeofcmds)
                if !loadCommands.isEmpty {
                    imageInfo["load_commands"] = loadCommands
                }
            }

            engine.report(module: name, key: "image.\(i)", value: imageInfo)
        }
    }

    private func parseLoadCommands(header: UnsafePointer<mach_header_64>, ncmds: UInt32, sizeofcmds: UInt32) -> [[String: Any]] {
        var results: [[String: Any]] = []
        var cmdPtr = UnsafeRawPointer(header).advanced(by: MemoryLayout<mach_header_64>.size)
        let endPtr = cmdPtr.advanced(by: Int(sizeofcmds))

        for _ in 0..<ncmds {
            guard cmdPtr < endPtr else { break }
            let cmd = cmdPtr.load(as: load_command.self)
            guard cmd.cmdsize >= MemoryLayout<load_command>.size, cmdPtr.advanced(by: Int(cmd.cmdsize)) <= endPtr else { break }

            switch cmd.cmd {
            case UInt32(LC_SEGMENT_64):
                let seg = cmdPtr.load(as: segment_command_64.self)
                let segname = withUnsafePointer(to: seg.segname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
                }
                results.append([
                    "cmd": "LC_SEGMENT_64",
                    "segname": segname,
                    "vmaddr": String(format: "0x%llx", seg.vmaddr),
                    "vmsize": String(format: "0x%llx", seg.vmsize),
                    "fileoff": seg.fileoff,
                    "filesize": seg.filesize,
                    "maxprot": String(format: "0x%x", seg.maxprot),
                    "initprot": String(format: "0x%x", seg.initprot),
                    "nsects": seg.nsects,
                ])

            case UInt32(LC_UUID):
                let uuidCmd = cmdPtr.load(as: uuid_command.self)
                let uuid = withUnsafePointer(to: uuidCmd.uuid) { ptr in
                    ptr.withMemoryRebound(to: UInt8.self, capacity: 16) { bytes in
                        (0..<16).map { String(format: "%02X", bytes[$0]) }.joined()
                    }
                }
                results.append(["cmd": "LC_UUID", "uuid": uuid])

            case UInt32(LC_ID_DYLIB), UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB):
                let dylibCmd = cmdPtr.load(as: dylib_command.self)
                let offset = Int(dylibCmd.dylib.name.offset)
                let cmdName: String
                switch cmd.cmd {
                case UInt32(LC_ID_DYLIB): cmdName = "LC_ID_DYLIB"
                case UInt32(LC_LOAD_DYLIB): cmdName = "LC_LOAD_DYLIB"
                case UInt32(LC_LOAD_WEAK_DYLIB): cmdName = "LC_LOAD_WEAK_DYLIB"
                case UInt32(LC_REEXPORT_DYLIB): cmdName = "LC_REEXPORT_DYLIB"
                default: cmdName = "LC_DYLIB_\(cmd.cmd)"
                }
                if offset < Int(cmd.cmdsize) {
                    let namePtr = cmdPtr.advanced(by: offset).assumingMemoryBound(to: CChar.self)
                    let dylibName = String(cString: namePtr)
                    results.append([
                        "cmd": cmdName,
                        "name": dylibName,
                        "timestamp": dylibCmd.dylib.timestamp,
                        "current_version": dylibCmd.dylib.current_version,
                        "compat_version": dylibCmd.dylib.compatibility_version,
                    ])
                }

            case UInt32(LC_VERSION_MIN_TVOS):
                let verCmd = cmdPtr.load(as: version_min_command.self)
                results.append([
                    "cmd": "LC_VERSION_MIN_TVOS",
                    "version": "\(verCmd.version >> 16).\((verCmd.version >> 8) & 0xFF).\(verCmd.version & 0xFF)",
                    "sdk": "\(verCmd.sdk >> 16).\((verCmd.sdk >> 8) & 0xFF).\(verCmd.sdk & 0xFF)",
                ])

            case UInt32(LC_BUILD_VERSION):
                let buildCmd = cmdPtr.load(as: build_version_command.self)
                results.append([
                    "cmd": "LC_BUILD_VERSION",
                    "platform": buildCmd.platform,
                    "minos": "\(buildCmd.minos >> 16).\((buildCmd.minos >> 8) & 0xFF).\(buildCmd.minos & 0xFF)",
                    "sdk": "\(buildCmd.sdk >> 16).\((buildCmd.sdk >> 8) & 0xFF).\(buildCmd.sdk & 0xFF)",
                    "ntools": buildCmd.ntools,
                ])

            case UInt32(LC_SOURCE_VERSION):
                results.append(["cmd": "LC_SOURCE_VERSION"])

            case UInt32(LC_RPATH):
                let rpathCmd = cmdPtr.load(as: rpath_command.self)
                let offset = Int(rpathCmd.path.offset)
                if offset < Int(cmd.cmdsize) {
                    let pathPtr = cmdPtr.advanced(by: offset).assumingMemoryBound(to: CChar.self)
                    results.append(["cmd": "LC_RPATH", "path": String(cString: pathPtr)])
                }

            default:
                break // Skip less interesting commands to keep output manageable
            }

            cmdPtr = cmdPtr.advanced(by: Int(cmd.cmdsize))
        }

        return results
    }

    // MARK: - Private framework probing

    private func probePrivateFrameworks(engine: ReconEngine) {
        let fm = FileManager.default
        let fwPath = "/System/Library/PrivateFrameworks"

        guard let frameworks = try? fm.contentsOfDirectory(atPath: fwPath) else {
            engine.reportError(module: name, key: "private_frameworks", error: "cannot list \(fwPath)")
            return
        }

        let interestingSymbols: [String] = [
            "sandbox_check", "sandbox_extension_issue_file",
            "sandbox_extension_consume", "csops", "csops_audittoken",
            "memorystatus_control", "proc_listallpids", "proc_pidinfo",
            "proc_pidfdinfo", "proc_name", "posix_spawn",
            "posix_spawnattr_setflags", "task_for_pid",
            "host_get_special_port", "IOServiceGetMatchingService",
            "IORegistryEntryCreateCFProperties", "MGCopyAnswer",
            "SBSSpringBoardServerPort", "BSAuditTokenTaskHasEntitlement",
            "SecTaskCopyValueForEntitlement",
            "xpc_connection_create_mach_service",
        ]

        engine.report(module: name, key: "private_frameworks_count", value: frameworks.count)

        for fw in frameworks.sorted() where fw.hasSuffix(".framework") {
            let fwName = (fw as NSString).deletingPathExtension
            let fullPath = "\(fwPath)/\(fw)/\(fwName)"

            // Try RTLD_NOLOAD first (already loaded?)
            var handle = dlopen(fullPath, RTLD_LAZY | RTLD_NOLOAD)
            let wasAlreadyLoaded = handle != nil

            if handle == nil {
                handle = dlopen(fullPath, RTLD_LAZY)
            }

            if let handle = handle {
                var foundSymbols: [String] = []
                for sym in interestingSymbols {
                    if dlsym(handle, sym) != nil {
                        foundSymbols.append(sym)
                    }
                }

                engine.report(module: name, key: "framework.\(fwName)", value: [
                    "loaded": true,
                    "was_already_loaded": wasAlreadyLoaded,
                    "symbols_found": foundSymbols,
                ])

                // Probe MGCopyAnswer if found
                if fwName == "MobileGestalt" || foundSymbols.contains("MGCopyAnswer") {
                    probeMGCopyAnswer(handle: handle, engine: engine)
                }

                if !wasAlreadyLoaded {
                    dlclose(handle)
                }
            } else {
                let err: String
                if let errPtr = dlerror() {
                    err = String(cString: errPtr)
                } else {
                    err = "unknown"
                }
                engine.report(module: name, key: "framework.\(fwName)", value: [
                    "loaded": false,
                    "error": err,
                ])
            }
        }
    }

    private func probeMGCopyAnswer(handle: UnsafeMutableRawPointer, engine: ReconEngine) {
        typealias MGCopyAnswerFunc = @convention(c) (CFString) -> CFTypeRef?
        guard let sym = dlsym(handle, "MGCopyAnswer") else { return }
        let mgCopyAnswer = unsafeBitCast(sym, to: MGCopyAnswerFunc.self)

        let keys = [
            "UniqueDeviceID", "SerialNumber", "ProductType", "HardwareModel",
            "BuildVersion", "DeviceName", "WifiAddress", "BluetoothAddress",
            "InternalBuild", "DeviceColor", "DeviceEnclosureColor", "RegionCode",
            "DiskUsage", "ModelNumber", "SIMTrayStatus", "PartitionType",
            "UserAssignedDeviceName", "CPUArchitecture", "KernelVersion",
            "FirmwareVersion", "HWModelStr", "BoardId", "ChipID",
            "DeviceClassNumber", "HasBaseband", "UniqueChipID",
        ]

        for key in keys {
            if let val = mgCopyAnswer(key as CFString) {
                let desc: String
                if CFGetTypeID(val) == CFStringGetTypeID() {
                    desc = val as! String
                } else if CFGetTypeID(val) == CFNumberGetTypeID() {
                    desc = "\(val)"
                } else if CFGetTypeID(val) == CFBooleanGetTypeID() {
                    desc = "\(CFBooleanGetValue((val as! CFBoolean)))"
                } else if CFGetTypeID(val) == CFDictionaryGetTypeID() {
                    if let d = val as? NSDictionary,
                       let jsonData = try? JSONSerialization.data(withJSONObject: d, options: [.sortedKeys]),
                       let jsonStr = String(data: jsonData, encoding: .utf8) {
                        desc = jsonStr
                    } else {
                        desc = "\(val)"
                    }
                } else {
                    desc = "\(val)"
                }
                engine.report(module: name, key: "gestalt.\(key)", value: desc)
            } else {
                engine.reportError(module: name, key: "gestalt.\(key)", error: "nil result")
            }
        }
    }

    // MARK: - ASLR info

    private func recordASLRInfo(engine: ReconEngine) {
        // Main executable slide
        if _dyld_image_count() > 0 {
            let mainSlide = _dyld_get_image_vmaddr_slide(0)
            engine.report(module: name, key: "main_executable_slide", value: String(format: "0x%llx", mainSlide))

            if let mainHeader = _dyld_get_image_header(0) {
                engine.report(module: name, key: "main_executable_address", value: String(format: "0x%llx", UInt(bitPattern: mainHeader)))
            }
        }

        // Shared cache base — look for dyld_shared_cache_find_iterate_text or read from header
        // The shared cache base can be inferred from any system library's load address
        for i in 0..<_dyld_image_count() {
            guard let namePtr = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: namePtr)
            if imageName.hasPrefix("/usr/lib/") || imageName.hasPrefix("/System/Library/") {
                if let headerPtr = _dyld_get_image_header(i) {
                    let addr = UInt(bitPattern: headerPtr)
                    let slide = _dyld_get_image_vmaddr_slide(i)
                    engine.report(module: name, key: "shared_cache_sample", value: [
                        "image": imageName,
                        "header_address": String(format: "0x%llx", addr),
                        "slide": String(format: "0x%llx", slide),
                        "unslid_address": String(format: "0x%llx", addr &- UInt(bitPattern: slide)),
                    ])
                    break
                }
            }
        }
    }
}
