// SandboxProfilerModule.swift
// Probes the app sandbox by testing sandbox_check() for all known operations,
// attempting empirical file I/O on sensitive paths, and trying sandbox extensions.
// Reveals which operations the sandbox profile allows or denies for this process.

import Foundation

final class SandboxProfilerModule: ReconModule {
    let name = "SandboxProfiler"
    let timeout: TimeInterval = 120

    // sandbox_check signature: int sandbox_check(pid_t pid, const char *operation, int type, ...)
    // type 0 = SANDBOX_FILTER_NONE, type 1 = SANDBOX_FILTER_PATH, type 2 = SANDBOX_FILTER_GLOBAL_NAME
    private typealias SandboxCheckFunc = @convention(c) (Int32, UnsafePointer<CChar>, Int32) -> Int32
    private typealias SandboxCheckPathFunc = @convention(c) (Int32, UnsafePointer<CChar>, Int32, UnsafePointer<CChar>) -> Int32
    private typealias SandboxCheckNameFunc = @convention(c) (Int32, UnsafePointer<CChar>, Int32, UnsafePointer<CChar>) -> Int32
    private typealias SandboxExtIssueFileFunc = @convention(c) (UnsafePointer<CChar>, Int32, UnsafePointer<CChar>, Int32) -> UnsafeMutablePointer<CChar>?
    private typealias SandboxExtConsumeFunc = @convention(c) (UnsafePointer<CChar>) -> Int64
    private typealias SandboxContainerPathFunc = @convention(c) (Int32) -> UnsafeMutablePointer<CChar>?

    func run(engine: ReconEngine) {
        let pid = getpid()

        let handle = dlopen(nil, RTLD_NOW)
        let sbCheckPtr = dlsym(handle, "sandbox_check")
        let sbCheckPathPtr = dlsym(handle, "sandbox_check")
        let sbCheckNamePtr = dlsym(handle, "sandbox_check")
        let sbExtIssuePtr = dlsym(handle, "sandbox_extension_issue_file")
        let sbExtConsumePtr = dlsym(handle, "sandbox_extension_consume")
        let sbContainerPathPtr = dlsym(handle, "sandbox_container_path_for_pid")

        engine.report(module: name, key: "sandbox_check_available", value: sbCheckPtr != nil)
        engine.report(module: name, key: "sandbox_extension_issue_file_available", value: sbExtIssuePtr != nil)
        engine.report(module: name, key: "sandbox_extension_consume_available", value: sbExtConsumePtr != nil)
        engine.report(module: name, key: "sandbox_container_path_for_pid_available", value: sbContainerPathPtr != nil)

        // Try to get our sandbox container path
        if let containerFn = sbContainerPathPtr {
            let fn = unsafeBitCast(containerFn, to: SandboxContainerPathFunc.self)
            if let result = fn(pid) {
                engine.report(module: name, key: "container_path", value: String(cString: result))
            } else {
                engine.report(module: name, key: "container_path", value: "nil_returned")
            }
        }

        // --- sandbox_check for operations with SANDBOX_FILTER_NONE (type 0) ---
        let noFilterOps: [String] = [
            "process-fork", "process-exec", "process-exec-interpreter",
            "process-info-pidinfo", "process-info-listpids", "process-info-rusage",
            "process-info-codesignature", "process-info-dirtycontrol", "process-info-setcontrol",
            "signal",
            "network-outbound", "network-inbound", "network-bind",
            "system-socket", "system-kext-load", "system-privilege",
            "job-creation", "hid-control",
            "lsopen", "distributed-notification-post",
            "mach-priv-host-port", "mach-priv-task-port",
            "ipc-sysv-shm", "ipc-sysv-sem", "ipc-sysv-msg"
        ]

        if let checkFnPtr = sbCheckPtr {
            let checkFn = unsafeBitCast(checkFnPtr, to: SandboxCheckFunc.self)

            for op in noFilterOps {
                let result = op.withCString { cOp -> Int32 in
                    return checkFn(pid, cOp, 0)
                }
                let allowed = result == 0
                engine.report(module: name, key: "sandbox_check_\(op)", value: [
                    "operation": op,
                    "filter": "none",
                    "result": result,
                    "allowed": allowed,
                    "errno": allowed ? 0 : Int(errno)
                ] as [String: Any])
            }
        }

        // --- sandbox_check for file operations with SANDBOX_FILTER_PATH (type 1) ---
        let fileOps: [String] = [
            "file-read-data", "file-read-metadata",
            "file-write-data", "file-write-metadata",
            "file-write-create", "file-write-unlink",
            "file-write-flags", "file-write-mode",
            "file-write-owner", "file-write-setugid",
            "file-write-xattr", "file-read-xattr",
            "file-mount", "file-unmount", "file-ioctl"
        ]

        let testPaths: [String] = [
            "/etc/passwd", "/etc/hosts", "/var/log/system.log",
            "/private/var/mobile", "/private/var/root",
            "/System/Library/Caches", "/Library/Preferences",
            "/tmp/sandbox_test", NSHomeDirectory(),
            NSTemporaryDirectory()
        ]

        if let checkFnPtr = sbCheckPathPtr {
            let checkPathFn = unsafeBitCast(checkFnPtr, to: SandboxCheckPathFunc.self)

            for op in fileOps {
                for path in testPaths {
                    let result = op.withCString { cOp -> Int32 in
                        return path.withCString { cPath -> Int32 in
                            return checkPathFn(pid, cOp, 1, cPath)
                        }
                    }
                    let allowed = result == 0
                    engine.report(module: name, key: "sandbox_check_file", value: [
                        "operation": op,
                        "path": path,
                        "result": result,
                        "allowed": allowed
                    ] as [String: Any])
                }
            }
        }

        // --- sandbox_check for mach/name operations with SANDBOX_FILTER_GLOBAL_NAME (type 2) ---
        let machOps: [String] = [
            "mach-lookup", "mach-register", "mach-task-name", "mach-per-user-lookup"
        ]
        let testServiceNames: [String] = [
            "com.apple.springboard", "com.apple.backboardd",
            "com.apple.PineBoard", "com.apple.securityd",
            "com.apple.lsd", "com.apple.mediaserverd",
            "com.apple.syslogd", "com.apple.containermanagerd",
            "com.apple.sandboxd", "com.apple.wifid",
            "com.apple.bluetoothd", "com.apple.locationd"
        ]

        if let checkFnPtr = sbCheckNamePtr {
            let checkNameFn = unsafeBitCast(checkFnPtr, to: SandboxCheckNameFunc.self)

            for op in machOps {
                for svcName in testServiceNames {
                    let result = op.withCString { cOp -> Int32 in
                        return svcName.withCString { cName -> Int32 in
                            return checkNameFn(pid, cOp, 2, cName)
                        }
                    }
                    let allowed = result == 0
                    engine.report(module: name, key: "sandbox_check_mach", value: [
                        "operation": op,
                        "service_name": svcName,
                        "result": result,
                        "allowed": allowed
                    ] as [String: Any])
                }
            }
        }

        // --- sandbox_check for IPC operations with SANDBOX_FILTER_GLOBAL_NAME ---
        let ipcNameOps: [String] = [
            "ipc-posix-shm-read-data", "ipc-posix-shm-write-data",
            "ipc-posix-shm-write-create", "ipc-posix-shm-write-unlink",
            "ipc-posix-sem-create", "ipc-posix-sem-open",
            "ipc-posix-sem-post", "ipc-posix-sem-wait", "ipc-posix-sem-unlink"
        ]
        let testShmNames = ["/com.apple.test", "com.apple.shm_test"]

        if let checkFnPtr = sbCheckNamePtr {
            let checkNameFn = unsafeBitCast(checkFnPtr, to: SandboxCheckNameFunc.self)
            for op in ipcNameOps {
                for shmName in testShmNames {
                    let result = op.withCString { cOp -> Int32 in
                        return shmName.withCString { cName -> Int32 in
                            return checkNameFn(pid, cOp, 2, cName)
                        }
                    }
                    engine.report(module: name, key: "sandbox_check_ipc", value: [
                        "operation": op,
                        "name": shmName,
                        "result": result,
                        "allowed": result == 0
                    ] as [String: Any])
                }
            }
        }

        // --- sandbox_check for sysctl and iokit ---
        let sysOps: [String] = [
            "sysctl-read", "sysctl-write",
            "iokit-open", "iokit-set-properties", "iokit-get-properties",
            "user-preference-read", "user-preference-write",
            "nvram-get", "nvram-set", "nvram-delete"
        ]
        if let checkFnPtr = sbCheckPtr {
            let checkFn = unsafeBitCast(checkFnPtr, to: SandboxCheckFunc.self)
            for op in sysOps {
                let result = op.withCString { cOp -> Int32 in
                    return checkFn(pid, cOp, 0)
                }
                engine.report(module: name, key: "sandbox_check_sys", value: [
                    "operation": op,
                    "filter": "none",
                    "result": result,
                    "allowed": result == 0
                ] as [String: Any])
            }
        }

        // --- Empirical file access tests ---
        let empiricalPaths: [String] = [
            "/etc/passwd", "/etc/hosts", "/etc/resolv.conf",
            "/var/log/system.log", "/var/log/syslog",
            "/private/var/mobile", "/private/var/mobile/Library",
            "/private/var/root",
            "/usr/libexec", "/usr/standalone",
            "/private/var/db/timezone",
            "/private/var/MobileAsset", "/private/var/containers",
            "/System/Library/Caches", "/Library/Preferences"
        ]

        for path in empiricalPaths {
            // Test read
            let readFd = open(path, O_RDONLY)
            let readResult: [String: Any]
            if readFd >= 0 {
                readResult = ["path": path, "mode": "O_RDONLY", "success": true, "fd": readFd]
                close(readFd)
            } else {
                readResult = [
                    "path": path,
                    "mode": "O_RDONLY",
                    "success": false,
                    "errno": Int(errno),
                    "error": String(cString: strerror(errno))
                ]
            }
            engine.report(module: name, key: "empirical_file_read", value: readResult)

            // Test write
            let writeFd = open(path, O_WRONLY)
            let writeResult: [String: Any]
            if writeFd >= 0 {
                writeResult = ["path": path, "mode": "O_WRONLY", "success": true, "fd": writeFd]
                close(writeFd)
            } else {
                writeResult = [
                    "path": path,
                    "mode": "O_WRONLY",
                    "success": false,
                    "errno": Int(errno),
                    "error": String(cString: strerror(errno))
                ]
            }
            engine.report(module: name, key: "empirical_file_write", value: writeResult)
        }

        // Test creating a file in NSTemporaryDirectory (should succeed)
        let tmpTestPath = NSTemporaryDirectory() + "sandbox_write_test_\(ProcessInfo.processInfo.globallyUniqueString)"
        let createFd = open(tmpTestPath, O_CREAT | O_WRONLY, 0o644)
        if createFd >= 0 {
            engine.report(module: name, key: "empirical_tmp_create", value: [
                "path": tmpTestPath, "success": true
            ] as [String: Any])
            close(createFd)
            unlink(tmpTestPath)
        } else {
            engine.report(module: name, key: "empirical_tmp_create", value: [
                "path": tmpTestPath, "success": false,
                "errno": Int(errno), "error": String(cString: strerror(errno))
            ] as [String: Any])
        }

        // --- Sandbox extension tests ---
        if let issueFnPtr = sbExtIssuePtr, let consumeFnPtr = sbExtConsumePtr {
            let issueFn = unsafeBitCast(issueFnPtr, to: SandboxExtIssueFileFunc.self)
            let consumeFn = unsafeBitCast(consumeFnPtr, to: SandboxExtConsumeFunc.self)

            // Try issuing read extensions for various paths
            let extTestPaths = [
                "/etc/passwd", "/var/log/system.log",
                NSHomeDirectory(), NSTemporaryDirectory()
            ]
            // Extension types: 1 = read, 2 = read-write
            let extTypes: [(String, Int32)] = [("read", 1), ("read-write", 2)]

            for path in extTestPaths {
                for (typeName, typeVal) in extTypes {
                    let token = "com.apple.app-sandbox.read".withCString { cls -> UnsafeMutablePointer<CChar>? in
                        return path.withCString { cPath -> UnsafeMutablePointer<CChar>? in
                            return issueFn(cls, typeVal, cPath, 0)
                        }
                    }
                    if let token = token {
                        let tokenStr = String(cString: token)
                        let consumeResult = consumeFn(token)
                        engine.report(module: name, key: "sandbox_extension", value: [
                            "path": path,
                            "type": typeName,
                            "issued": true,
                            "token_prefix": String(tokenStr.prefix(40)),
                            "consume_result": consumeResult
                        ] as [String: Any])
                        free(token)
                    } else {
                        engine.report(module: name, key: "sandbox_extension", value: [
                            "path": path,
                            "type": typeName,
                            "issued": false,
                            "errno": Int(errno),
                            "error": String(cString: strerror(errno))
                        ] as [String: Any])
                    }
                }
            }
        } else {
            engine.reportError(module: name, key: "sandbox_extension_test", error: "sandbox_extension functions not available via dlsym")
        }

        if handle != nil {
            dlclose(handle)
        }
    }
}
