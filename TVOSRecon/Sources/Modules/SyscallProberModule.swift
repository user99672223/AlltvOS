// SyscallProberModule.swift
// Systematically tests key syscalls and walks syscall numbers 0-600 to map which
// system calls are accessible from the sandbox. Uses sigsetjmp/siglongjmp to survive
// signals from blocked syscalls. Probes fork, exec, ptrace, mmap, csops, and more.

import Foundation

// Global jump buffer for signal recovery - must be file-scope for C signal handler
private var syscallJmpBuf = sigjmp_buf()
private var syscallSignalCaught: Int32 = 0

// C-compatible signal handler
private func syscallSignalHandler(sig: Int32) {
    syscallSignalCaught = sig
    siglongjmp(&syscallJmpBuf, 1)
}

final class SyscallProberModule: ReconModule {
    let name = "SyscallProber"
    let timeout: TimeInterval = 120

    func run(engine: ReconEngine) {
        probeKeySystemCalls(engine: engine)
        probePtraceVariants(engine: engine)
        probeMemoryMapping(engine: engine)
        probePrivilegedOps(engine: engine)
        probeCsops(engine: engine)
        probeMemoryStatus(engine: engine)
        probeKasInfo(engine: engine)
        walkSyscallTable(engine: engine)
    }

    // MARK: - Key System Calls

    private func probeKeySystemCalls(engine: ReconEngine) {
        // fork
        do {
            let pid = fork()
            if pid == 0 {
                _exit(0) // child exits immediately
            } else if pid > 0 {
                var status: Int32 = 0
                waitpid(pid, &status, 0)
                engine.report(module: name, key: "syscall_fork", value: [
                    "success": true, "child_pid": pid
                ] as [String: Any])
            } else {
                engine.report(module: name, key: "syscall_fork", value: [
                    "success": false, "errno": Int(errno), "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
        }

        // vfork - too dangerous in practice, just report we're skipping actual call
        // since vfork shares address space and can corrupt parent
        engine.report(module: name, key: "syscall_vfork", value: [
            "tested": false,
            "reason": "vfork shares address space, unsafe to test; fork result is representative"
        ] as [String: Any])

        // execve with invalid path
        do {
            let testPath = "/nonexistent_binary_for_test"
            let ret = testPath.withCString { path -> Int32 in
                var argv: [UnsafeMutablePointer<CChar>?] = [nil]
                var envp: [UnsafeMutablePointer<CChar>?] = [nil]
                return execve(path, &argv, &envp)
            }
            engine.report(module: name, key: "syscall_execve", value: [
                "success": false, "return": ret, "errno": Int(errno),
                "error": String(cString: strerror(errno))
            ] as [String: Any])
        }

        // posix_spawn
        do {
            var pid: pid_t = 0
            let testPath = "/bin/echo"
            var argv: [UnsafeMutablePointer<CChar>?] = [
                strdup("echo"), strdup("test"), nil
            ]
            defer { argv.compactMap { $0 }.forEach { free($0) } }

            var envp: [UnsafeMutablePointer<CChar>?] = [nil]
            let ret = posix_spawn(&pid, testPath, nil, nil, &argv, &envp)
            if ret == 0 {
                var status: Int32 = 0
                waitpid(pid, &status, 0)
                engine.report(module: name, key: "syscall_posix_spawn", value: [
                    "success": true, "pid": pid, "exit_status": status
                ] as [String: Any])
            } else {
                engine.report(module: name, key: "syscall_posix_spawn", value: [
                    "success": false, "return": ret, "errno": ret,
                    "error": String(cString: strerror(ret))
                ] as [String: Any])
            }
        }

        // kqueue/kevent
        do {
            let kq = kqueue()
            if kq >= 0 {
                engine.report(module: name, key: "syscall_kqueue", value: [
                    "success": true, "fd": kq
                ] as [String: Any])
                close(kq)
            } else {
                engine.report(module: name, key: "syscall_kqueue", value: [
                    "success": false, "errno": Int(errno), "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
        }

        // kill(1, 0) - can we signal init?
        do {
            let ret = kill(1, 0)
            engine.report(module: name, key: "syscall_kill_init", value: [
                "target_pid": 1, "signal": 0, "success": ret == 0,
                "errno": ret != 0 ? Int(errno) : 0,
                "error": ret != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
        }

        // chroot
        do {
            let ret = chroot("/tmp")
            engine.report(module: name, key: "syscall_chroot", value: [
                "success": ret == 0, "errno": Int(errno),
                "error": String(cString: strerror(errno))
            ] as [String: Any])
        }

        // chdir to restricted
        let restrictedPaths = ["/private/var/root", "/System", "/private/var/mobile"]
        for path in restrictedPaths {
            let oldCwd = FileManager.default.currentDirectoryPath
            let ret = chdir(path)
            engine.report(module: name, key: "syscall_chdir", value: [
                "path": path, "success": ret == 0,
                "errno": ret != 0 ? Int(errno) : 0,
                "error": ret != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
            if ret == 0 { chdir(oldCwd) }
        }
    }

    // MARK: - ptrace

    private func probePtraceVariants(engine: ReconEngine) {
        // ptrace is often wrapped; use dlsym
        typealias PtraceFunc = @convention(c) (Int32, Int32, UnsafeMutableRawPointer?, Int32) -> Int32

        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        let ptraceFn: PtraceFunc?
        if let ptr = dlsym(handle, "ptrace") {
            ptraceFn = unsafeBitCast(ptr, to: PtraceFunc.self)
        } else {
            ptraceFn = nil
            engine.reportError(module: name, key: "ptrace_dlsym", error: "ptrace not found via dlsym")
        }

        let PT_DENY_ATTACH: Int32 = 31
        let PT_TRACE_ME: Int32 = 0
        let PT_ATTACHEXC: Int32 = 14

        let tests: [(String, Int32, Int32)] = [
            ("PT_TRACE_ME", PT_TRACE_ME, 0),
            ("PT_DENY_ATTACH", PT_DENY_ATTACH, 0),
            ("PT_ATTACHEXC", PT_ATTACHEXC, getpid())
        ]

        for (testName, request, targetPid) in tests {
            if let fn = ptraceFn {
                errno = 0
                let ret = fn(request, targetPid, nil, 0)
                engine.report(module: name, key: "ptrace", value: [
                    "request": testName, "pid": targetPid,
                    "return": ret, "errno": Int(errno),
                    "error": errno != 0 ? String(cString: strerror(errno)) : ""
                ] as [String: Any])
            }
        }
    }

    // MARK: - Memory Mapping

    private func probeMemoryMapping(engine: ReconEngine) {
        let pageSize = Int(getpagesize())

        // mmap with PROT_EXEC
        do {
            let ptr = mmap(nil, pageSize, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0)
            if ptr != MAP_FAILED {
                engine.report(module: name, key: "mmap_prot_exec", value: [
                    "success": true, "address": String(format: "0x%lx", Int(bitPattern: ptr))
                ] as [String: Any])
                munmap(ptr, pageSize)
            } else {
                engine.report(module: name, key: "mmap_prot_exec", value: [
                    "success": false, "errno": Int(errno), "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
        }

        // mmap with MAP_JIT
        do {
            let MAP_JIT: Int32 = 0x0800
            let ptr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0)
            if ptr != MAP_FAILED {
                engine.report(module: name, key: "mmap_map_jit", value: [
                    "success": true, "address": String(format: "0x%lx", Int(bitPattern: ptr))
                ] as [String: Any])

                // Try mprotect to add PROT_EXEC on JIT page
                let mpRet = mprotect(ptr, pageSize, PROT_READ | PROT_EXEC)
                engine.report(module: name, key: "mprotect_jit_exec", value: [
                    "success": mpRet == 0,
                    "errno": mpRet != 0 ? Int(errno) : 0
                ] as [String: Any])

                munmap(ptr, pageSize)
            } else {
                engine.report(module: name, key: "mmap_map_jit", value: [
                    "success": false, "errno": Int(errno), "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
        }

        // mprotect adding PROT_EXEC to data page
        do {
            let ptr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0)
            if ptr != MAP_FAILED {
                let ret = mprotect(ptr, pageSize, PROT_READ | PROT_WRITE | PROT_EXEC)
                engine.report(module: name, key: "mprotect_add_exec", value: [
                    "success": ret == 0,
                    "errno": ret != 0 ? Int(errno) : 0,
                    "error": ret != 0 ? String(cString: strerror(errno)) : ""
                ] as [String: Any])
                munmap(ptr, pageSize)
            }
        }
    }

    // MARK: - Privileged Operations

    private func probePrivilegedOps(engine: ReconEngine) {
        // setuid/setgid variants
        let credTests: [(String, () -> Int32)] = [
            ("setuid(0)", { setuid(0) }),
            ("setgid(0)", { setgid(0) }),
            ("seteuid(0)", { seteuid(0) }),
            ("setegid(0)", { setegid(0) })
        ]

        for (testName, fn) in credTests {
            errno = 0
            let ret = fn()
            engine.report(module: name, key: "syscall_priv", value: [
                "call": testName, "return": ret,
                "errno": Int(errno),
                "error": errno != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
        }

        // mount/unmount
        do {
            errno = 0
            let ret = Darwin.unmount("/tmp", 0)
            engine.report(module: name, key: "syscall_unmount", value: [
                "path": "/tmp", "return": ret,
                "errno": Int(errno), "error": String(cString: strerror(errno))
            ] as [String: Any])
        }

        // reboot
        do {
            typealias RebootFunc = @convention(c) (Int32) -> Int32
            let handle = dlopen(nil, RTLD_NOW)
            if let fn = dlsym(handle, "reboot") {
                let rebootFn = unsafeBitCast(fn, to: RebootFunc.self)
                errno = 0
                let ret = rebootFn(0) // RB_AUTOBOOT
                engine.report(module: name, key: "syscall_reboot", value: [
                    "return": ret, "errno": Int(errno),
                    "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
            if handle != nil { dlclose(handle) }
        }

        // settimeofday
        do {
            var tv = timeval()
            errno = 0
            let ret = settimeofday(&tv, nil)
            engine.report(module: name, key: "syscall_settimeofday", value: [
                "return": ret, "errno": Int(errno),
                "error": String(cString: strerror(errno))
            ] as [String: Any])
        }
    }

    // MARK: - csops

    private func probeCsops(engine: ReconEngine) {
        typealias CsopsFunc = @convention(c) (Int32, UInt32, UnsafeMutableRawPointer?, Int) -> Int32

        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        guard let csopsPtr = dlsym(handle, "csops") else {
            engine.reportError(module: name, key: "csops", error: "csops not found via dlsym")
            return
        }

        let csops = unsafeBitCast(csopsPtr, to: CsopsFunc.self)
        let pid = getpid()

        // CS_OPS_STATUS (0)
        do {
            var flags: UInt32 = 0
            errno = 0
            let ret = csops(pid, 0, &flags, MemoryLayout<UInt32>.size)
            if ret == 0 {
                engine.report(module: name, key: "csops_status", value: [
                    "success": true, "flags": flags,
                    "flags_hex": String(format: "0x%08x", flags),
                    "CS_VALID": (flags & 0x00000001) != 0,
                    "CS_ADHOC": (flags & 0x00000002) != 0,
                    "CS_GET_TASK_ALLOW": (flags & 0x00000004) != 0,
                    "CS_INSTALLER": (flags & 0x00000008) != 0,
                    "CS_FORCED_LV": (flags & 0x00000010) != 0,
                    "CS_INVALID_ALLOWED": (flags & 0x00000020) != 0,
                    "CS_HARD": (flags & 0x00000100) != 0,
                    "CS_KILL": (flags & 0x00000200) != 0,
                    "CS_CHECK_EXPIRATION": (flags & 0x00000400) != 0,
                    "CS_RESTRICT": (flags & 0x00000800) != 0,
                    "CS_ENFORCEMENT": (flags & 0x00001000) != 0,
                    "CS_REQUIRE_LV": (flags & 0x00002000) != 0,
                    "CS_ENTITLEMENTS_VALIDATED": (flags & 0x00004000) != 0,
                    "CS_NVRAM_UNRESTRICTED": (flags & 0x00008000) != 0,
                    "CS_RUNTIME": (flags & 0x00010000) != 0,
                    "CS_LINKER_SIGNED": (flags & 0x00020000) != 0,
                    "CS_EXEC_SET_HARD": (flags & 0x00100000) != 0,
                    "CS_EXEC_SET_KILL": (flags & 0x00200000) != 0,
                    "CS_EXEC_SET_ENFORCEMENT": (flags & 0x00400000) != 0,
                    "CS_EXEC_INHERIT_SIP": (flags & 0x00800000) != 0,
                    "CS_KILLED": (flags & 0x01000000) != 0,
                    "CS_DYLD_PLATFORM": (flags & 0x02000000) != 0,
                    "CS_PLATFORM_BINARY": (flags & 0x04000000) != 0,
                    "CS_PLATFORM_PATH": (flags & 0x08000000) != 0,
                    "CS_DEBUGGED": (flags & 0x10000000) != 0,
                    "CS_SIGNED": (flags & 0x20000000) != 0,
                    "CS_DEV_CODE": (flags & 0x40000000) != 0
                ] as [String: Any])
            } else {
                engine.report(module: name, key: "csops_status", value: [
                    "success": false, "errno": Int(errno)
                ] as [String: Any])
            }
        }

        // CS_OPS_ENTITLEMENTS_BLOB (7)
        do {
            var bufSize = 65536
            var buf = [UInt8](repeating: 0, count: bufSize)
            errno = 0
            let ret = csops(pid, 7, &buf, bufSize)
            if ret == 0 {
                // The blob has a magic + length header (8 bytes) then XML data
                if bufSize > 8 {
                    let xmlData = Data(buf[8...])
                    if let xmlStr = String(data: xmlData, encoding: .utf8)?
                        .trimmingCharacters(in: .controlCharacters)
                        .trimmingCharacters(in: .whitespaces) {
                        engine.report(module: name, key: "csops_entitlements_blob", value: [
                            "success": true,
                            "blob_size": buf.count,
                            "xml_prefix": String(xmlStr.prefix(500))
                        ] as [String: Any])
                    }
                }
            } else {
                engine.report(module: name, key: "csops_entitlements_blob", value: [
                    "success": false, "errno": Int(errno),
                    "error": String(cString: strerror(errno))
                ] as [String: Any])
            }
        }

        // CS_OPS_SET_STATUS (6) - try clearing CS_RESTRICT
        do {
            var newFlags: UInt32 = 0
            errno = 0
            let ret = csops(pid, 6, &newFlags, MemoryLayout<UInt32>.size)
            engine.report(module: name, key: "csops_set_status", value: [
                "success": ret == 0,
                "errno": Int(errno),
                "error": errno != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
        }

        // CS_OPS_MARKINVALID (1), CS_OPS_MARKHARD (2), CS_OPS_MARKKILL (3)
        for (opName, opCode) in [("MARKINVALID", UInt32(1)), ("MARKHARD", UInt32(2)), ("MARKKILL", UInt32(3))] {
            var dummy: UInt32 = 0
            errno = 0
            let ret = csops(pid, opCode, &dummy, MemoryLayout<UInt32>.size)
            engine.report(module: name, key: "csops_\(opName.lowercased())", value: [
                "operation": opName, "return": ret,
                "errno": Int(errno)
            ] as [String: Any])
        }
    }

    // MARK: - memorystatus_control

    private func probeMemoryStatus(engine: ReconEngine) {
        typealias MemoryStatusFunc = @convention(c) (UInt32, Int32, UInt32, UnsafeMutableRawPointer?, Int) -> Int32

        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        guard let fnPtr = dlsym(handle, "memorystatus_control") else {
            engine.reportError(module: name, key: "memorystatus_control", error: "not found via dlsym")
            return
        }

        let fn = unsafeBitCast(fnPtr, to: MemoryStatusFunc.self)

        // MEMORYSTATUS_CMD_GET_PRIORITY_LIST = 1
        var bufSize = 65536
        var buf = [UInt8](repeating: 0, count: bufSize)
        errno = 0
        let ret = fn(1, 0, 0, &buf, bufSize)
        engine.report(module: name, key: "memorystatus_get_priority_list", value: [
            "return": ret,
            "errno": Int(errno),
            "error": errno != 0 ? String(cString: strerror(errno)) : "",
            "bytes_returned": ret >= 0 ? ret : 0
        ] as [String: Any])

        // MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK = 5
        errno = 0
        let ret2 = fn(5, getpid(), 100, nil, 0)
        engine.report(module: name, key: "memorystatus_set_jetsam_hwm", value: [
            "return": ret2,
            "errno": Int(errno),
            "error": errno != 0 ? String(cString: strerror(errno)) : ""
        ] as [String: Any])
    }

    // MARK: - kas_info

    private func probeKasInfo(engine: ReconEngine) {
        // kas_info syscall (SYS_kas_info = 439)
        // int kas_info(int selector, void *value, size_t *size)
        // selector 0 = KAS_INFO_KERNEL_TEXT_SLIDE_SELECTOR
        typealias KasInfoFunc = @convention(c) (Int32, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?) -> Int32

        let handle = dlopen(nil, RTLD_NOW)
        defer { if handle != nil { dlclose(handle) } }

        if let fnPtr = dlsym(handle, "kas_info") {
            let fn = unsafeBitCast(fnPtr, to: KasInfoFunc.self)
            var slide: UInt64 = 0
            var size = MemoryLayout<UInt64>.size
            errno = 0
            let ret = fn(0, &slide, &size)
            engine.report(module: name, key: "kas_info_kernel_text_slide", value: [
                "return": ret,
                "slide": ret == 0 ? String(format: "0x%llx", slide) : "unavailable",
                "errno": Int(errno),
                "error": errno != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
        } else {
            // Try via syscall number directly
            var slide: UInt64 = 0
            var size = MemoryLayout<UInt64>.size
            errno = 0
            let ret = tvr_syscall3(439, 0, &slide, &size)
            engine.report(module: name, key: "kas_info_kernel_text_slide", value: [
                "method": "syscall_439",
                "return": ret,
                "slide": ret == 0 ? String(format: "0x%llx", slide) : "unavailable",
                "errno": Int(errno)
            ] as [String: Any])
        }
    }

    // MARK: - Syscall Table Walk

    private func walkSyscallTable(engine: ReconEngine) {
        // Install signal handlers with sigsetjmp recovery
        let oldSIGSYS = installSignalHandler(SIGSYS)
        let oldSIGBUS = installSignalHandler(SIGBUS)
        let oldSIGSEGV = installSignalHandler(SIGSEGV)

        defer {
            restoreSignalHandler(SIGSYS, old: oldSIGSYS)
            restoreSignalHandler(SIGBUS, old: oldSIGBUS)
            restoreSignalHandler(SIGSEGV, old: oldSIGSEGV)
        }

        var results: [[String: Any]] = []

        for sysNum in 0...600 {
            syscallSignalCaught = 0
            errno = 0

            var result: [String: Any] = ["syscall_number": sysNum]

            if sigsetjmp(&syscallJmpBuf, 1) == 0 {
                // Normal path - try the syscall
                let ret = tvr_syscall0(Int32(sysNum))
                let savedErrno = errno

                result["return"] = ret
                result["errno"] = Int(savedErrno)

                if ret == 0 && savedErrno == 0 {
                    result["status"] = "succeeded"
                } else {
                    let errName = errnoName(savedErrno)
                    result["status"] = errName
                    result["error"] = String(cString: strerror(savedErrno))
                }
            } else {
                // Jumped here from signal handler
                result["status"] = signalName(syscallSignalCaught)
                result["signal"] = Int(syscallSignalCaught)
            }

            results.append(result)

            // Report in batches to avoid overwhelming
            if results.count >= 50 {
                engine.report(module: name, key: "syscall_walk_batch", value: results)
                results.removeAll()
            }
        }

        if !results.isEmpty {
            engine.report(module: name, key: "syscall_walk_batch", value: results)
        }

        // Summary
        engine.report(module: name, key: "syscall_walk_complete", value: [
            "range": "0-600", "total_tested": 601
        ] as [String: Any])
    }

    // MARK: - Helpers

    private func installSignalHandler(_ sig: Int32) -> sigaction {
        var newAction = sigaction()
        newAction.__sigaction_u.__sa_handler = syscallSignalHandler
        sigemptyset(&newAction.sa_mask)
        newAction.sa_flags = 0

        var oldAction = sigaction()
        sigaction(sig, &newAction, &oldAction)
        return oldAction
    }

    private func restoreSignalHandler(_ sig: Int32, old: sigaction) {
        var oldCopy = old
        sigaction(sig, &oldCopy, nil)
    }

    private func errnoName(_ err: Int32) -> String {
        switch err {
        case EPERM: return "EPERM"
        case ENOENT: return "ENOENT"
        case ESRCH: return "ESRCH"
        case EINTR: return "EINTR"
        case EIO: return "EIO"
        case ENXIO: return "ENXIO"
        case ENOEXEC: return "ENOEXEC"
        case EBADF: return "EBADF"
        case ECHILD: return "ECHILD"
        case EACCES: return "EACCES"
        case EFAULT: return "EFAULT"
        case EBUSY: return "EBUSY"
        case EEXIST: return "EEXIST"
        case EINVAL: return "EINVAL"
        case ENOSYS: return "ENOSYS"
        case ENOTSUP: return "ENOTSUP"
        case 0: return "SUCCESS"
        default: return "ERRNO_\(err)"
        }
    }

    private func signalName(_ sig: Int32) -> String {
        switch sig {
        case SIGSYS: return "SIGSYS"
        case SIGBUS: return "SIGBUS"
        case SIGSEGV: return "SIGSEGV"
        case SIGKILL: return "SIGKILL"
        case SIGABRT: return "SIGABRT"
        case SIGTRAP: return "SIGTRAP"
        case SIGILL: return "SIGILL"
        default: return "SIGNAL_\(sig)"
        }
    }
}
