// DispatchAndGCDProbeModule: Probes GCD queue behavior, thread pool limits, QoS classes,
// pthread scheduling, and dispatch source availability. Reveals runtime concurrency constraints.

import Foundation

final class DispatchAndGCDProbeModule: ReconModule {
    let name = "DispatchAndGCDProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeQoSClasses(engine: engine)
        probeMainQueue(engine: engine)
        measureThreadPool(engine: engine)
        probePthreadAttributes(engine: engine)
        probePthreadScheduling(engine: engine)
        probeDispatchSources(engine: engine)
    }

    private func probeQoSClasses(engine: ReconEngine) {
        let classes: [(String, DispatchQoS)] = [
            ("userInteractive", .userInteractive),
            ("userInitiated", .userInitiated),
            ("default", .default),
            ("utility", .utility),
            ("background", .background)
        ]

        for (label, qos) in classes {
            let queue = DispatchQueue(label: "com.tvosrecon.qos.\(label)", qos: qos)
            let sem = DispatchSemaphore(value: 0)
            var worked = false
            queue.async {
                worked = true
                sem.signal()
            }
            let result = sem.wait(timeout: .now() + 2)
            let status: String
            if result == .timedOut {
                status = "timeout"
            } else {
                status = worked ? "ok" : "failed"
            }
            engine.report(module: name, key: "qos_\(label)", value: status)
        }
    }

    private func probeMainQueue(engine: ReconEngine) {
        if let label = String(validatingUTF8: __dispatch_queue_get_label(nil)) {
            engine.report(module: name, key: "main_queue_label", value: label)
        } else {
            engine.report(module: name, key: "main_queue_label", value: "nil")
        }
    }

    private func measureThreadPool(engine: ReconEngine) {
        let concurrentCount = 64
        let counter = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var maxConcurrent = 0
        var currentConcurrent = 0
        let group = DispatchGroup()
        let concurrentQueue = DispatchQueue(label: "com.tvosrecon.pool", attributes: .concurrent)

        for _ in 0..<concurrentCount {
            group.enter()
            concurrentQueue.async {
                lock.lock()
                currentConcurrent += 1
                if currentConcurrent > maxConcurrent {
                    maxConcurrent = currentConcurrent
                }
                lock.unlock()

                // Block briefly to measure concurrency
                Thread.sleep(forTimeInterval: 0.1)

                lock.lock()
                currentConcurrent -= 1
                lock.unlock()
                group.leave()
            }
        }
        // Wait up to 10 seconds
        _ = group.wait(timeout: .now() + 10)
        engine.report(module: name, key: "thread_pool_max_concurrent", value: "\(maxConcurrent)")
        engine.report(module: name, key: "thread_pool_tasks_submitted", value: "\(concurrentCount)")
    }

    private func probePthreadAttributes(engine: ReconEngine) {
        let thread = pthread_self()

        // Stack size
        var attr = pthread_attr_t()
        if pthread_attr_init(&attr) == 0 {
            var stackSize: Int = 0
            if pthread_attr_getstacksize(&attr, &stackSize) == 0 {
                engine.report(module: name, key: "pthread_default_stacksize", value: "\(stackSize)")
            }

            var guardSize: Int = 0
            if pthread_attr_getguardsize(&attr, &guardSize) == 0 {
                engine.report(module: name, key: "pthread_default_guardsize", value: "\(guardSize)")
            }
            pthread_attr_destroy(&attr)
        }

        // Current thread stack
        let stackAddr = pthread_get_stackaddr_np(thread)
        let stackSz = pthread_get_stacksize_np(thread)
        engine.report(module: name, key: "current_thread_stack_addr", value: String(format: "0x%lx", UInt(bitPattern: stackAddr)))
        engine.report(module: name, key: "current_thread_stack_size", value: "\(stackSz)")

        // Scheduling policy
        var policy: Int32 = 0
        var param = sched_param()
        if pthread_getschedparam(thread, &policy, &param) == 0 {
            let policyName: String
            switch policy {
            case SCHED_OTHER: policyName = "SCHED_OTHER"
            case SCHED_FIFO:  policyName = "SCHED_FIFO"
            case SCHED_RR:    policyName = "SCHED_RR"
            default:          policyName = "unknown(\(policy))"
            }
            engine.report(module: name, key: "pthread_sched_policy", value: policyName)
            engine.report(module: name, key: "pthread_sched_priority", value: "\(param.sched_priority)")
        }
    }

    private func probePthreadScheduling(engine: ReconEngine) {
        let thread = pthread_self()
        var param = sched_param()
        param.sched_priority = 31
        let result = pthread_setschedparam(thread, SCHED_RR, &param)
        if result == 0 {
            engine.report(module: name, key: "pthread_setschedparam_RR_31", value: "success")
            // Restore
            param.sched_priority = 0
            pthread_setschedparam(thread, SCHED_OTHER, &param)
        } else {
            engine.reportError(module: name, key: "pthread_setschedparam_RR_31", error: "errno=\(result) (\(String(cString: strerror(result))))")
        }

        // Try FIFO
        param.sched_priority = 1
        let fifoResult = pthread_setschedparam(thread, SCHED_FIFO, &param)
        if fifoResult == 0 {
            engine.report(module: name, key: "pthread_setschedparam_FIFO_1", value: "success")
            param.sched_priority = 0
            pthread_setschedparam(thread, SCHED_OTHER, &param)
        } else {
            engine.reportError(module: name, key: "pthread_setschedparam_FIFO_1", error: "errno=\(fifoResult) (\(String(cString: strerror(fifoResult))))")
        }
    }

    private func probeDispatchSources(engine: ReconEngine) {
        // DISPATCH_SOURCE_TYPE_TIMER
        do {
            let source = DispatchSource.makeTimerSource(queue: .global())
            source.setEventHandler {}
            source.schedule(deadline: .now() + 999, repeating: .never)
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_TIMER", value: "ok")
        }

        // DISPATCH_SOURCE_TYPE_DATA_ADD
        do {
            let source = DispatchSource.makeUserDataAddSource(queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_DATA_ADD", value: "ok")
        }

        // DISPATCH_SOURCE_TYPE_DATA_OR
        do {
            let source = DispatchSource.makeUserDataOrSource(queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_DATA_OR", value: "ok")
        }

        #if canImport(Darwin)
        // DISPATCH_SOURCE_TYPE_DATA_REPLACE (available on newer OS)
        if #available(tvOS 15.0, *) {
            let source = DispatchSource.makeUserDataReplaceSource(queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_DATA_REPLACE", value: "ok")
        }
        #endif

        // DISPATCH_SOURCE_TYPE_MEMORYPRESSURE
        do {
            let source = DispatchSource.makeMemoryPressureSource(eventMask: .all, queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_MEMORYPRESSURE", value: "ok")
        }

        // DISPATCH_SOURCE_TYPE_SIGNAL
        do {
            let source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_SIGNAL", value: "ok")
        }

        // DISPATCH_SOURCE_TYPE_READ - use a pipe fd
        do {
            var fds: [Int32] = [0, 0]
            if pipe(&fds) == 0 {
                let source = DispatchSource.makeReadSource(fileDescriptor: fds[0], queue: .global())
                source.setEventHandler {}
                source.activate()
                source.cancel()
                close(fds[0])
                close(fds[1])
                engine.report(module: name, key: "dispatch_source_READ", value: "ok")
            } else {
                engine.reportError(module: name, key: "dispatch_source_READ", error: "pipe() failed")
            }
        }

        // DISPATCH_SOURCE_TYPE_WRITE
        do {
            var fds: [Int32] = [0, 0]
            if pipe(&fds) == 0 {
                let source = DispatchSource.makeWriteSource(fileDescriptor: fds[1], queue: .global())
                source.setEventHandler {}
                source.activate()
                source.cancel()
                close(fds[0])
                close(fds[1])
                engine.report(module: name, key: "dispatch_source_WRITE", value: "ok")
            } else {
                engine.reportError(module: name, key: "dispatch_source_WRITE", error: "pipe() failed")
            }
        }

        // DISPATCH_SOURCE_TYPE_VNODE
        do {
            let tmpPath = NSTemporaryDirectory() + "tvosrecon_vnode_test"
            FileManager.default.createFile(atPath: tmpPath, contents: nil)
            let fd = open(tmpPath, O_RDONLY)
            if fd >= 0 {
                let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .all, queue: .global())
                source.setEventHandler {}
                source.activate()
                source.cancel()
                close(fd)
                engine.report(module: name, key: "dispatch_source_VNODE", value: "ok")
            } else {
                engine.reportError(module: name, key: "dispatch_source_VNODE", error: "open() failed, errno=\(errno)")
            }
            try? FileManager.default.removeItem(atPath: tmpPath)
        }

        // DISPATCH_SOURCE_TYPE_PROC
        do {
            let source = DispatchSource.makeProcessSource(identifier: getpid(), eventMask: .exit, queue: .global())
            source.setEventHandler {}
            source.activate()
            source.cancel()
            engine.report(module: name, key: "dispatch_source_PROC", value: "ok")
        }
    }
}
