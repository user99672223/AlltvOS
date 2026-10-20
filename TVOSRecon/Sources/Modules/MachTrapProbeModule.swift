// MachTrapProbeModule.swift
// Probes the Mach trap table (traps 0-127) to map which kernel traps are accessible
// from the app sandbox. Also tests thread state and exception port operations.
// Important for understanding the kernel-userspace boundary available to sideloaded apps.

import Foundation
import Darwin
import MachO

// Global jump buffer for signal recovery
private var trapJumpBuf = jmp_buf()
private var trapSignalCaught: Int32 = 0

private func trapSignalHandler(_ sig: Int32) {
    trapSignalCaught = sig
    longjmp(&trapJumpBuf, 1)
}

final class MachTrapProbeModule: ReconModule {
    let name = "MachTrapProbe"
    let timeout: TimeInterval = 90

    func run(engine: ReconEngine) {
        testNamedTraps(engine: engine)
        probeAllTraps(engine: engine)
        testThreadState(engine: engine)
        testExceptionPorts(engine: engine)
    }

    // MARK: - Named Mach Traps

    private func testNamedTraps(engine: ReconEngine) {
        // task_self_trap (26) — returns the task port
        do {
            let port = mach_task_self_
            engine.report(module: name, key: "trap_26_task_self", value: "port=\(port)")
        }

        // host_self_trap (27)
        do {
            let port = mach_host_self()
            engine.report(module: name, key: "trap_27_host_self", value: "port=\(port)")
        }

        // thread_self_trap (28)
        do {
            let port = mach_thread_self()
            engine.report(module: name, key: "trap_28_thread_self", value: "port=\(port)")
            mach_port_deallocate(mach_task_self_, port)
        }

        // mach_reply_port (29)
        do {
            let port = mach_reply_port()
            if port != MACH_PORT_NULL {
                engine.report(module: name, key: "trap_29_mach_reply_port", value: "port=\(port)")
                mach_port_deallocate(mach_task_self_, port)
            } else {
                engine.report(module: name, key: "trap_29_mach_reply_port", value: "returned MACH_PORT_NULL")
            }
        }

        // mach_timebase_info (89)
        do {
            var info = mach_timebase_info_data_t()
            let kr = mach_timebase_info(&info)
            engine.report(module: name, key: "trap_89_mach_timebase_info", value: "kr=\(kr) numer=\(info.numer) denom=\(info.denom)")
        }

        // semaphore_signal_trap (33)
        do {
            var semPort: semaphore_t = 0
            let createKr = semaphore_create(mach_task_self_, &semPort, SYNC_POLICY_FIFO, 0)
            if createKr == KERN_SUCCESS {
                let sigKr = semaphore_signal(semPort)
                engine.report(module: name, key: "trap_33_semaphore_signal", value: "kr=\(sigKr)")
                semaphore_destroy(mach_task_self_, semPort)
            } else {
                engine.report(module: name, key: "trap_33_semaphore_signal", value: "create_failed_kr=\(createKr)")
            }
        }

        // semaphore_wait_trap (36) — use signal first so it doesn't block
        do {
            var semPort: semaphore_t = 0
            let createKr = semaphore_create(mach_task_self_, &semPort, SYNC_POLICY_FIFO, 1)
            if createKr == KERN_SUCCESS {
                let waitKr = semaphore_wait(semPort)
                engine.report(module: name, key: "trap_36_semaphore_wait", value: "kr=\(waitKr)")
                semaphore_destroy(mach_task_self_, semPort)
            } else {
                engine.report(module: name, key: "trap_36_semaphore_wait", value: "create_failed_kr=\(createKr)")
            }
        }

        // mk_timer_create (91)
        do {
            typealias MkTimerCreateFn = @convention(c) () -> mach_port_t
            let handle = dlopen(nil, RTLD_LAZY)
            if let sym = dlsym(handle, "mk_timer_create") {
                let fn = unsafeBitCast(sym, to: MkTimerCreateFn.self)
                let port = fn()
                engine.report(module: name, key: "trap_91_mk_timer_create", value: "port=\(port)")
                if port != MACH_PORT_NULL {
                    // mk_timer_cancel (93)
                    typealias MkTimerCancelFn = @convention(c) (mach_port_t, UnsafeMutablePointer<UInt64>?) -> kern_return_t
                    if let cancelSym = dlsym(handle, "mk_timer_cancel") {
                        let cancelFn = unsafeBitCast(cancelSym, to: MkTimerCancelFn.self)
                        var resultTime: UInt64 = 0
                        let kr = cancelFn(port, &resultTime)
                        engine.report(module: name, key: "trap_93_mk_timer_cancel", value: "kr=\(kr)")
                    }

                    // mk_timer_arm (92)
                    typealias MkTimerArmFn = @convention(c) (mach_port_t, UInt64) -> kern_return_t
                    if let armSym = dlsym(handle, "mk_timer_arm") {
                        let armFn = unsafeBitCast(armSym, to: MkTimerArmFn.self)
                        let futureTime = mach_absolute_time() + 1_000_000_000
                        let kr = armFn(port, futureTime)
                        engine.report(module: name, key: "trap_92_mk_timer_arm", value: "kr=\(kr)")
                    }

                    mach_port_deallocate(mach_task_self_, port)
                }
            } else {
                engine.reportError(module: name, key: "trap_91_mk_timer_create", error: "dlsym failed")
            }
            dlclose(handle)
        }
    }

    // MARK: - Probe Mach Trap Table 0-127

    private func probeAllTraps(engine: ReconEngine) {
        let knownTraps: [Int32: String] = [
            10: "kern_invalid",
            12: "_kernelrpc_mach_vm_allocate_trap",
            14: "_kernelrpc_mach_vm_deallocate_trap",
            15: "_kernelrpc_mach_vm_protect_trap",
            16: "_kernelrpc_mach_vm_map_trap",
            17: "_kernelrpc_mach_port_allocate_trap",
            18: "_kernelrpc_mach_port_deallocate_trap",
            19: "_kernelrpc_mach_port_mod_refs_trap",
            20: "_kernelrpc_mach_port_move_member_trap",
            21: "_kernelrpc_mach_port_insert_right_trap",
            22: "_kernelrpc_mach_port_insert_member_trap",
            23: "_kernelrpc_mach_port_extract_member_trap",
            24: "_kernelrpc_mach_port_construct_trap",
            25: "_kernelrpc_mach_port_destruct_trap",
            26: "mach_reply_port / task_self_trap",
            27: "host_self_trap",
            28: "thread_self_trap",
            29: "mach_reply_port",
            31: "mach_msg_trap",
            32: "mach_msg_overwrite_trap",
            33: "semaphore_signal_trap",
            34: "semaphore_signal_all_trap",
            36: "semaphore_wait_trap",
            37: "semaphore_wait_signal_trap",
            38: "semaphore_timedwait_trap",
            39: "semaphore_timedwait_signal_trap",
            41: "_kernelrpc_mach_port_guard_trap",
            42: "_kernelrpc_mach_port_unguard_trap",
            43: "mach_generate_activity_id",
            44: "task_name_for_pid",
            45: "task_for_pid",
            46: "pid_for_task",
            48: "macx_swapon",
            49: "macx_swapoff",
            51: "macx_triggers",
            52: "macx_backing_store_suspend",
            53: "macx_backing_store_recovery",
            59: "swtch_pri",
            60: "swtch",
            61: "syscall_thread_switch",
            62: "clock_sleep_trap",
            89: "mach_timebase_info_trap",
            90: "mach_wait_until_trap",
            91: "mk_timer_create_trap",
            92: "mk_timer_arm_trap",
            93: "mk_timer_cancel_trap",
            94: "mk_timer_destroy_trap",
            100: "iokit_user_client_trap",
        ]

        // Install signal handlers
        var oldSIGSYS = sigaction()
        var oldSIGBUS = sigaction()
        var oldSIGSEGV = sigaction()

        var sa = sigaction()
        sa.__sigaction_u.__sa_handler = trapSignalHandler
        sigemptyset(&sa.sa_mask)
        sa.sa_flags = 0

        sigaction(SIGSYS, &sa, &oldSIGSYS)
        sigaction(SIGBUS, &sa, &oldSIGBUS)
        sigaction(SIGSEGV, &sa, &oldSIGSEGV)

        for trapNum: Int32 in 0..<128 {
            let trapName = knownTraps[trapNum] ?? "unknown"
            trapSignalCaught = 0

            if setjmp(&trapJumpBuf) == 0 {
                // Try calling the trap with syscall
                // On ARM64, Mach traps are negative syscall numbers
                let result = syscall(Int32(-trapNum))
                let err = errno
                engine.report(module: name, key: "trap_\(trapNum)", value: [
                    "name": trapName,
                    "result": result,
                    "errno": err,
                    "errno_name": String(cString: strerror(err))
                ] as [String: Any])
            } else {
                engine.report(module: name, key: "trap_\(trapNum)", value: [
                    "name": trapName,
                    "signal_caught": trapSignalCaught,
                    "signal_name": signalName(trapSignalCaught)
                ] as [String: Any])
            }
        }

        // Restore signal handlers
        sigaction(SIGSYS, &oldSIGSYS, nil)
        sigaction(SIGBUS, &oldSIGBUS, nil)
        sigaction(SIGSEGV, &oldSIGSEGV, nil)
    }

    // MARK: - Thread State

    private func testThreadState(engine: ReconEngine) {
        let thread = mach_thread_self()
        defer { mach_port_deallocate(mach_task_self_, thread) }

        // ARM_THREAD_STATE64 (flavor 6)
        do {
            var state = arm_thread_state64_t()
            var count = mach_msg_type_number_t(MemoryLayout<arm_thread_state64_t>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &state) { ptr in
                ptr.withMemoryRebound(to: natural_t.self, capacity: Int(count)) { natPtr in
                    thread_get_state(thread, ARM_THREAD_STATE64, natPtr, &count)
                }
            }
            engine.report(module: name, key: "thread_get_state_ARM_THREAD_STATE64", value: "kr=\(kr) (\(kr == KERN_SUCCESS ? "success" : "denied"))")
        }

        // ARM_NEON_STATE64 (flavor 17)
        do {
            var stateData = [natural_t](repeating: 0, count: 256)
            var count = mach_msg_type_number_t(256)
            let kr = thread_get_state(thread, 17, &stateData, &count)
            engine.report(module: name, key: "thread_get_state_ARM_NEON_STATE64", value: "kr=\(kr) count=\(count)")
        }

        // ARM_EXCEPTION_STATE64 (flavor 7)
        do {
            var stateData = [natural_t](repeating: 0, count: 16)
            var count = mach_msg_type_number_t(16)
            let kr = thread_get_state(thread, ARM_EXCEPTION_STATE64, &stateData, &count)
            engine.report(module: name, key: "thread_get_state_ARM_EXCEPTION_STATE64", value: "kr=\(kr) count=\(count)")
        }

        // ARM_DEBUG_STATE64 (flavor 15)
        do {
            var stateData = [natural_t](repeating: 0, count: 128)
            var count = mach_msg_type_number_t(128)
            let kr = thread_get_state(thread, 15, &stateData, &count)
            engine.report(module: name, key: "thread_get_state_ARM_DEBUG_STATE64", value: "kr=\(kr) count=\(count)")
        }

        // Try thread_set_state (should fail — setting state on our own running thread is meaningless, but test permission)
        do {
            var stateData = [natural_t](repeating: 0, count: 4)
            let count = mach_msg_type_number_t(4)
            let kr = thread_set_state(thread, ARM_EXCEPTION_STATE64, &stateData, count)
            engine.report(module: name, key: "thread_set_state_ARM_EXCEPTION_STATE64", value: "kr=\(kr)")
        }
    }

    // MARK: - Exception Ports

    private func testExceptionPorts(engine: ReconEngine) {
        let task = mach_task_self_

        // task_get_exception_ports
        do {
            var masks = [exception_mask_t](repeating: 0, count: 32)
            var ports = [mach_port_t](repeating: 0, count: 32)
            var behaviors = [exception_behavior_t](repeating: 0, count: 32)
            var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
            var count = mach_msg_type_number_t(32)

            let kr = task_get_exception_ports(
                task,
                exception_mask_t(EXC_MASK_ALL),
                &masks,
                &count,
                &ports,
                &behaviors,
                &flavors
            )
            engine.report(module: name, key: "task_get_exception_ports", value: "kr=\(kr) count=\(count)")
            if kr == KERN_SUCCESS {
                for i in 0..<Int(count) {
                    engine.report(module: name, key: "exception_port_\(i)", value: [
                        "mask": masks[i],
                        "port": ports[i],
                        "behavior": behaviors[i],
                        "flavor": flavors[i]
                    ] as [String: Any])
                }
            }
        }

        // task_set_exception_ports — try to set a handler for EXC_BAD_ACCESS
        do {
            var port: mach_port_t = 0
            let allocKr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port)
            if allocKr == KERN_SUCCESS {
                let insertKr = mach_port_insert_right(task, port, port, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
                engine.report(module: name, key: "mach_port_insert_right_for_exc", value: "kr=\(insertKr)")

                let setKr = task_set_exception_ports(
                    task,
                    exception_mask_t(EXC_MASK_BAD_ACCESS),
                    port,
                    Int32(EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
                    ARM_THREAD_STATE64
                )
                engine.report(module: name, key: "task_set_exception_ports", value: "kr=\(setKr)")

                mach_port_deallocate(task, port)
            } else {
                engine.reportError(module: name, key: "task_set_exception_ports", error: "port allocate failed: \(allocKr)")
            }
        }

        // task_swap_exception_ports
        do {
            var oldMasks = [exception_mask_t](repeating: 0, count: 32)
            var oldPorts = [mach_port_t](repeating: 0, count: 32)
            var oldBehaviors = [exception_behavior_t](repeating: 0, count: 32)
            var oldFlavors = [thread_state_flavor_t](repeating: 0, count: 32)
            var oldCount = mach_msg_type_number_t(32)

            let kr = task_swap_exception_ports(
                task,
                exception_mask_t(EXC_MASK_BAD_INSTRUCTION),
                MACH_PORT_NULL,
                Int32(EXCEPTION_DEFAULT),
                ARM_THREAD_STATE64,
                &oldMasks,
                &oldCount,
                &oldPorts,
                &oldBehaviors,
                &oldFlavors
            )
            engine.report(module: name, key: "task_swap_exception_ports", value: "kr=\(kr) old_count=\(oldCount)")
        }
    }

    private func signalName(_ sig: Int32) -> String {
        switch sig {
        case SIGSYS: return "SIGSYS"
        case SIGBUS: return "SIGBUS"
        case SIGSEGV: return "SIGSEGV"
        case SIGKILL: return "SIGKILL"
        case SIGABRT: return "SIGABRT"
        case SIGILL: return "SIGILL"
        case SIGTRAP: return "SIGTRAP"
        default: return "SIG\(sig)"
        }
    }
}
