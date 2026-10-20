// POSIXIPCProbeModule.swift
// TVOSRecon - Module 19: POSIX IPC Probe
//
// Tests POSIX and System V IPC mechanisms available from the sandbox.
// Shared memory, semaphores, message queues, pipes, socketpairs, unix domain
// sockets, and FIFOs each have distinct sandbox rules. Results show which
// inter-process communication primitives a sideloaded app can use.

import Foundation

final class POSIXIPCProbeModule: ReconModule {
    let name = "POSIXIPCProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeSharedMemory(engine: engine)
        probeKnownShmNames(engine: engine)
        probeNamedSemaphores(engine: engine)
        probeMessageQueues(engine: engine)
        probePipesAndSocketpairs(engine: engine)
        scanUnixSockets(engine: engine)
        probeMkfifo(engine: engine)
        probeSysVIPC(engine: engine)
        probeFlock(engine: engine)
    }

    // MARK: - POSIX Shared Memory

    private func probeSharedMemory(engine: ReconEngine) {
        let testName = "/tvosrecon_shm_test"

        // O_RDONLY
        let fdRd = tvr_shm_open(testName, O_RDONLY, 0)
        if fdRd >= 0 {
            engine.report(module: name, key: "shm_open_rdonly", value: "succeeded fd=\(fdRd)")
            close(fdRd)
        } else {
            engine.report(module: name, key: "shm_open_rdonly", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // O_RDWR | O_CREAT
        let fdRw = tvr_shm_open(testName, O_RDWR | O_CREAT, 0600)
        if fdRw >= 0 {
            engine.report(module: name, key: "shm_open_rdwr_creat", value: "succeeded fd=\(fdRw)")

            // Try ftruncate + mmap
            let truncRes = ftruncate(fdRw, 4096)
            engine.report(module: name, key: "shm_ftruncate", value: truncRes == 0 ? "succeeded" : "failed errno=\(errno) (\(errnoString()))")

            let ptr = mmap(nil, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fdRw, 0)
            if ptr != MAP_FAILED {
                engine.report(module: name, key: "shm_mmap_rw", value: "succeeded addr=\(String(format: "0x%lx", UInt(bitPattern: ptr)))")
                munmap(ptr, 4096)
            } else {
                engine.report(module: name, key: "shm_mmap_rw", value: "failed errno=\(errno) (\(errnoString()))")
            }

            close(fdRw)
            shm_unlink(testName)
        } else {
            engine.report(module: name, key: "shm_open_rdwr_creat", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // O_CREAT | O_EXCL
        let fdExcl = tvr_shm_open(testName, O_RDWR | O_CREAT | O_EXCL, 0600)
        if fdExcl >= 0 {
            engine.report(module: name, key: "shm_open_creat_excl", value: "succeeded fd=\(fdExcl)")
            close(fdExcl)
            shm_unlink(testName)
        } else {
            engine.report(module: name, key: "shm_open_creat_excl", value: "failed errno=\(errno) (\(errnoString()))")
        }
    }

    private func probeKnownShmNames(engine: ReconEngine) {
        let names = [
            "/com.apple.shm.diagnostic",
            "/com.apple.shm.notification_center",
            "/com.apple.AppleDatabaseChanged",
            "/apple.shm.cfprefsd.daemon",
            "/com.apple.featureflags.shm",
            "/com.apple.windowserver",
            "/com.apple.MTLCompilerService"
        ]
        for shmName in names {
            let fd = tvr_shm_open(shmName, O_RDONLY, 0)
            if fd >= 0 {
                var st = stat()
                let statRes = fstat(fd, &st)
                let size = statRes == 0 ? st.st_size : -1
                engine.report(module: name, key: "shm_known.\(shmName)", value: "accessible fd=\(fd) size=\(size)")
                close(fd)
            } else {
                engine.report(module: name, key: "shm_known.\(shmName)", value: "denied errno=\(errno) (\(errnoString()))")
            }
        }
    }

    // MARK: - Named Semaphores

    private func probeNamedSemaphores(engine: ReconEngine) {
        let testSemName = "/tvosrecon_sem_test"

        // sem_open create
        let sem = sem_open(testSemName, O_CREAT | O_EXCL, 0600, 1)
        if sem != SEM_FAILED {
            engine.report(module: name, key: "sem_open_create", value: "succeeded")

            // Try operations
            let waitRes = sem_trywait(sem)
            engine.report(module: name, key: "sem_trywait", value: waitRes == 0 ? "succeeded" : "failed errno=\(errno)")

            let postRes = sem_post(sem)
            engine.report(module: name, key: "sem_post", value: postRes == 0 ? "succeeded" : "failed errno=\(errno)")

            var val: Int32 = 0
            let getRes = sem_getvalue(sem, &val)
            engine.report(module: name, key: "sem_getvalue", value: getRes == 0 ? "value=\(val)" : "failed errno=\(errno)")

            sem_close(sem)
            sem_unlink(testSemName)
        } else {
            engine.report(module: name, key: "sem_open_create", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // Try open existing system ones
        let knownSems = ["/com.apple.audit", "/com.apple.security"]
        for semName in knownSems {
            let s = sem_open(semName, 0)
            if s != SEM_FAILED {
                engine.report(module: name, key: "sem_known.\(semName)", value: "accessible")
                sem_close(s)
            } else {
                engine.report(module: name, key: "sem_known.\(semName)", value: "denied errno=\(errno) (\(errnoString()))")
            }
        }

        // Unnamed semaphore
        var unnamedSem = sem_t()
        let initRes = sem_init(&unnamedSem, 0, 1)
        engine.report(module: name, key: "sem_init_unnamed", value: initRes == 0 ? "succeeded" : "failed errno=\(errno) (\(errnoString()))")
        if initRes == 0 {
            sem_destroy(&unnamedSem)
        }
    }

    // MARK: - POSIX Message Queues

    private func probeMessageQueues(engine: ReconEngine) {
        // mq_open is not available on Darwin / tvOS; we probe via dlsym
        typealias MqOpenFunc = @convention(c) (UnsafePointer<CChar>, Int32) -> Int32
        if let mqSym = dlsym(dlopen(nil, RTLD_LAZY), "mq_open") {
            let mqOpen = unsafeBitCast(mqSym, to: MqOpenFunc.self)
            let result = mqOpen("/tvosrecon_mq_test", O_RDONLY)
            if result >= 0 {
                engine.report(module: name, key: "mq_open", value: "succeeded fd=\(result)")
                // mq_close would be needed
            } else {
                engine.report(module: name, key: "mq_open", value: "failed errno=\(errno) (\(errnoString())) — likely ENOSYS")
            }
        } else {
            engine.report(module: name, key: "mq_open", value: "symbol not found — POSIX MQ not implemented on Darwin")
        }
    }

    // MARK: - Pipes and Socketpairs

    private func probePipesAndSocketpairs(engine: ReconEngine) {
        // pipe()
        var pipeFds: [Int32] = [0, 0]
        let pipeRes = pipe(&pipeFds)
        if pipeRes == 0 {
            engine.report(module: name, key: "pipe", value: "succeeded read_fd=\(pipeFds[0]) write_fd=\(pipeFds[1])")

            // Write and read test
            let testData: [UInt8] = [0x41, 0x42, 0x43, 0x44]
            let written = write(pipeFds[1], testData, testData.count)
            engine.report(module: name, key: "pipe_write", value: "wrote \(written) bytes")

            var buf = [UInt8](repeating: 0, count: 4)
            let readCount = read(pipeFds[0], &buf, 4)
            engine.report(module: name, key: "pipe_read", value: "read \(readCount) bytes")

            close(pipeFds[0])
            close(pipeFds[1])
        } else {
            engine.report(module: name, key: "pipe", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // socketpair(AF_UNIX, SOCK_STREAM)
        var spFds: [Int32] = [0, 0]
        let spRes = socketpair(AF_UNIX, SOCK_STREAM, 0, &spFds)
        if spRes == 0 {
            engine.report(module: name, key: "socketpair_stream", value: "succeeded fd0=\(spFds[0]) fd1=\(spFds[1])")
            close(spFds[0])
            close(spFds[1])
        } else {
            engine.report(module: name, key: "socketpair_stream", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // socketpair(AF_UNIX, SOCK_DGRAM)
        var spDgram: [Int32] = [0, 0]
        let spDRes = socketpair(AF_UNIX, SOCK_DGRAM, 0, &spDgram)
        if spDRes == 0 {
            engine.report(module: name, key: "socketpair_dgram", value: "succeeded fd0=\(spDgram[0]) fd1=\(spDgram[1])")
            close(spDgram[0])
            close(spDgram[1])
        } else {
            engine.report(module: name, key: "socketpair_dgram", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // socketpair(AF_UNIX, SOCK_SEQPACKET)
        var spSeq: [Int32] = [0, 0]
        let spSRes = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, &spSeq)
        if spSRes == 0 {
            engine.report(module: name, key: "socketpair_seqpacket", value: "succeeded fd0=\(spSeq[0]) fd1=\(spSeq[1])")
            close(spSeq[0])
            close(spSeq[1])
        } else {
            engine.report(module: name, key: "socketpair_seqpacket", value: "failed errno=\(errno) (\(errnoString()))")
        }
    }

    // MARK: - Unix Domain Socket Scan

    private func scanUnixSockets(engine: ReconEngine) {
        let dirs = [
            "/var/run",
            "/tmp",
            "/private/var/run",
            "/private/var/tmp",
            "/private/var/db"
        ]

        for dir in dirs {
            let fm = FileManager.default
            guard let enumerator = fm.enumerator(atPath: dir) else {
                engine.report(module: name, key: "unix_scan.\(dir)", value: "cannot_enumerate")
                continue
            }

            var socketCount = 0
            while let file = enumerator.nextObject() as? String {
                let fullPath = (dir as NSString).appendingPathComponent(file)
                var st = stat()
                guard lstat(fullPath, &st) == 0 else { continue }

                if (st.st_mode & S_IFMT) == S_IFSOCK {
                    socketCount += 1

                    // Try connecting
                    let connectResult = tryConnectUnix(path: fullPath)
                    engine.report(module: name, key: "unix_socket.\(fullPath)",
                                  value: "found type=socket connect=\(connectResult)")
                }

                // Limit depth to avoid long scans
                if socketCount > 100 { break }
            }

            engine.report(module: name, key: "unix_scan.\(dir).count", value: socketCount)
        }
    }

    private func tryConnectUnix(path: String) -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return "socket_failed" }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = path.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            return "path_too_long"
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { sunPathPtr in
            sunPathPtr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    _ = memcpy(dest, src.baseAddress!, pathBytes.count)
                }
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let res = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                connect(fd, saPtr, addrLen)
            }
        }

        if res == 0 {
            return "connected"
        } else {
            return "refused errno=\(errno) (\(errnoString()))"
        }
    }

    // MARK: - mkfifo

    private func probeMkfifo(engine: ReconEngine) {
        let tmpDir = NSTemporaryDirectory()
        let fifoPath = (tmpDir as NSString).appendingPathComponent("tvosrecon_fifo_test")

        // Clean up first
        unlink(fifoPath)

        let res = mkfifo(fifoPath, 0600)
        if res == 0 {
            engine.report(module: name, key: "mkfifo", value: "succeeded path=\(fifoPath)")

            // Verify it's a FIFO
            var st = stat()
            // Unqualified: Darwin.stat resolves to the struct type, not the function.
            if stat(fifoPath, &st) == 0 {
                let isFifo = (st.st_mode & S_IFMT) == S_IFIFO
                engine.report(module: name, key: "mkfifo_verify", value: "is_fifo=\(isFifo)")
            }

            unlink(fifoPath)
        } else {
            engine.report(module: name, key: "mkfifo", value: "failed errno=\(errno) (\(errnoString()))")
        }
    }

    // MARK: - System V IPC

    private func probeSysVIPC(engine: ReconEngine) {
        // shmget
        let shmId = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600)
        if shmId >= 0 {
            engine.report(module: name, key: "sysv_shmget", value: "succeeded id=\(shmId)")

            let ptr = shmat(shmId, nil, 0)
            if ptr != UnsafeMutableRawPointer(bitPattern: -1) {
                engine.report(module: name, key: "sysv_shmat", value: "succeeded")
                shmdt(ptr)
            } else {
                engine.report(module: name, key: "sysv_shmat", value: "failed errno=\(errno) (\(errnoString()))")
            }

            shmctl(shmId, IPC_RMID, nil)
        } else {
            engine.report(module: name, key: "sysv_shmget", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // semget
        let semId = semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600)
        if semId >= 0 {
            engine.report(module: name, key: "sysv_semget", value: "succeeded id=\(semId)")
            tvr_semctl(semId, 0, IPC_RMID)
        } else {
            engine.report(module: name, key: "sysv_semget", value: "failed errno=\(errno) (\(errnoString()))")
        }

        // msgget
        let msgId = msgget(IPC_PRIVATE, IPC_CREAT | 0o600)
        if msgId >= 0 {
            engine.report(module: name, key: "sysv_msgget", value: "succeeded id=\(msgId)")
            msgctl(msgId, IPC_RMID, nil)
        } else {
            engine.report(module: name, key: "sysv_msgget", value: "failed errno=\(errno) (\(errnoString()))")
        }
    }

    // MARK: - flock

    private func probeFlock(engine: ReconEngine) {
        let paths = [
            NSTemporaryDirectory() + "/tvosrecon_flock_test",
            "/etc/hosts",
            "/var/log/system.log"
        ]

        for path in paths {
            // Create test file if it's our temp file
            if path.contains("tvosrecon") {
                FileManager.default.createFile(atPath: path, contents: nil)
            }

            let fd = open(path, O_RDONLY)
            if fd >= 0 {
                // Shared lock
                let sharedRes = flock(fd, LOCK_SH | LOCK_NB)
                engine.report(module: name, key: "flock_shared.\(path)",
                              value: sharedRes == 0 ? "succeeded" : "failed errno=\(errno)")
                if sharedRes == 0 {
                    flock(fd, LOCK_UN)
                }

                // Exclusive lock
                let exclRes = flock(fd, LOCK_EX | LOCK_NB)
                engine.report(module: name, key: "flock_exclusive.\(path)",
                              value: exclRes == 0 ? "succeeded" : "failed errno=\(errno)")
                if exclRes == 0 {
                    flock(fd, LOCK_UN)
                }

                close(fd)
            } else {
                engine.report(module: name, key: "flock.\(path)", value: "open_failed errno=\(errno) (\(errnoString()))")
            }
        }

        // Clean up
        unlink(NSTemporaryDirectory() + "/tvosrecon_flock_test")
    }

    private func errnoString() -> String {
        return String(cString: strerror(errno))
    }
}
