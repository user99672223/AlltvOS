// MachTrapProbeModule.swift
// Probes named Mach traps, thread state and exception port operations from the app sandbox.
// The 0-127 trap-table sweep is not run on tvOS because it needs syscall(), which is unavailable there.
// Important for understanding the kernel-userspace boundary available to sideloaded apps.

import Foundation
import Darwin
import MachO

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

        // mach_reply_port (29) — not declared in the SDK headers the bridging header imports,
        // so it is resolved at runtime, the same way as the mk_timer traps below
        do {
            typealias MachReplyPortFn = @convention(c) () -> mach_port_t
            let handle = dlopen(nil, RTLD_LAZY)
            if let sym = dlsym(handle, "mach_reply_port") {
                let fn = unsafeBitCast(sym, to: MachReplyPortFn.self)
                let port = fn()
                if port != MACH_PORT_NULL {
                    engine.report(module: name, key: "trap_29_mach_reply_port", value: "port=\(port)")
                    mach_port_deallocate(mach_task_self_, port)
                } else {
                    engine.report(module: name, key: "trap_29_mach_reply_port", value: "returned MACH_PORT_NULL")
                }
            } else {
                engine.reportError(module: name, key: "trap_29_mach_reply_port", error: "dlsym failed")
            }
            dlclose(handle)
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

    // MARK: - Mach Trap Table 0-127 (not run on tvOS)

    private func probeAllTraps(engine: ReconEngine) {
        // The sweep called every trap number through syscall() and recovered from faults with
        // setjmp/longjmp. syscall() is unavailable on tvOS, and that fault recovery cannot be used
        // from Swift, so the sweep is removed and its skip is recorded here.
        engine.reportError(module: name, key: "trap_table_0_127", error: "skipped: syscall() is unavailable on tvOS")
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
        // task_get/set/swap_exception_ports are unavailable on tvOS, so this body is only compiled for other platforms.
        #if !os(tvOS)
        let task = mach_task_self_

        // task_get_exception_ports
        do {
            // EXC_MASK_ALL is not usable from Swift here, so its value is spelled out: bits 1-9 and 11-13,
            // i.e. EXC_BAD_ACCESS..EXC_CORPSE_NOTIFY without EXC_CRASH (bit 10). Check against the SDK header.
            let excMaskAll: exception_mask_t = 0x3BFE

            var masks = [exception_mask_t](repeating: 0, count: 32)
            var ports = [mach_port_t](repeating: 0, count: 32)
            var behaviors = [exception_behavior_t](repeating: 0, count: 32)
            var flavors = [thread_state_flavor_t](repeating: 0, count: 32)
            var count = mach_msg_type_number_t(32)

            let kr = task_get_exception_ports(
                task,
                excMaskAll,
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

                // Combine EXCEPTION_DEFAULT and MACH_EXCEPTION_CODES as UInt32 and reinterpret the bits.
                // Int32(...) of a value with the high bit set (MACH_EXCEPTION_CODES) traps at runtime.
                let behaviorBits = UInt32(truncatingIfNeeded: EXCEPTION_DEFAULT) | UInt32(truncatingIfNeeded: MACH_EXCEPTION_CODES)
                let behavior = exception_behavior_t(truncatingIfNeeded: behaviorBits)

                let setKr = task_set_exception_ports(
                    task,
                    exception_mask_t(EXC_MASK_BAD_ACCESS),
                    port,
                    behavior,
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
                mach_port_t(MACH_PORT_NULL),
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
        #else
        engine.report(module: name, key: "exception_ports", value: "exception_ports_unavailable_on_tvOS")
        #endif
    }
}
