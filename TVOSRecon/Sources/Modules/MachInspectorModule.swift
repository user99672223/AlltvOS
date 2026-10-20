// MachInspectorModule.swift
// Probes the Mach kernel interface: task info, port enumeration, host
// statistics, special ports, thread state, and privileged operations
// like task_for_pid. Maps the Mach IPC surface reachable from the
// sandbox and reveals resource limits, VM statistics, and CPU load.

import Foundation

final class MachInspectorModule: ReconModule {
    let name = "MachInspector"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        collectTaskInfo(engine: engine)
        enumeratePorts(engine: engine)
        collectHostInfo(engine: engine)
        collectHostStatistics(engine: engine)
        probeSpecialPorts(engine: engine)
        probeTaskForPid(engine: engine)
        collectThreadInfo(engine: engine)
        probeClockServices(engine: engine)
    }

    // MARK: - Task Info

    private func collectTaskInfo(engine: ReconEngine) {
        let task = mach_task_self_

        // MACH_TASK_BASIC_INFO
        do {
            var info = mach_task_basic_info()
            var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(MACH_TASK_BASIC_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.mach_basic_info", value: [
                    "virtual_size": info.virtual_size,
                    "resident_size": info.resident_size,
                    "resident_size_max": info.resident_size_max,
                    "user_time_seconds": info.user_time.seconds,
                    "user_time_microseconds": info.user_time.microseconds,
                    "system_time_seconds": info.system_time.seconds,
                    "system_time_microseconds": info.system_time.microseconds,
                    "policy": info.policy,
                    "suspend_count": info.suspend_count,
                ])
            } else {
                engine.reportError(module: name, key: "task.mach_basic_info", error: "kern_return=\(kr)")
            }
        }

        // TASK_VM_INFO
        do {
            var info = task_vm_info()
            var count = mach_msg_type_number_t(MemoryLayout<task_vm_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(TASK_VM_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.vm_info", value: [
                    "virtual_size": info.virtual_size,
                    "resident_size": info.resident_size,
                    "resident_size_peak": info.resident_size_peak,
                    "region_count": info.region_count,
                    "page_size": info.page_size,
                    "device": info.device,
                    "device_peak": info.device_peak,
                    "internal": info.internal,
                    "internal_peak": info.internal_peak,
                    "external": info.external,
                    "external_peak": info.external_peak,
                    "reusable": info.reusable,
                    "reusable_peak": info.reusable_peak,
                    "purgeable_volatile_pmap": info.purgeable_volatile_pmap,
                    "purgeable_volatile_resident": info.purgeable_volatile_resident,
                    "purgeable_volatile_virtual": info.purgeable_volatile_virtual,
                    "compressed": info.compressed,
                    "compressed_peak": info.compressed_peak,
                    "compressed_lifetime": info.compressed_lifetime,
                    "phys_footprint": info.phys_footprint,
                    "min_address": String(format: "0x%llx", info.min_address),
                    "max_address": String(format: "0x%llx", info.max_address),
                ])
            } else {
                engine.reportError(module: name, key: "task.vm_info", error: "kern_return=\(kr)")
            }
        }

        // TASK_THREAD_TIMES_INFO
        do {
            var info = task_thread_times_info()
            var count = mach_msg_type_number_t(MemoryLayout<task_thread_times_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(TASK_THREAD_TIMES_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.thread_times", value: [
                    "user_time_seconds": info.user_time.seconds,
                    "user_time_microseconds": info.user_time.microseconds,
                    "system_time_seconds": info.system_time.seconds,
                    "system_time_microseconds": info.system_time.microseconds,
                ])
            } else {
                engine.reportError(module: name, key: "task.thread_times", error: "kern_return=\(kr)")
            }
        }

        // TASK_ABSOLUTETIME_INFO
        do {
            var info = task_absolutetime_info()
            var count = mach_msg_type_number_t(MemoryLayout<task_absolutetime_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(TASK_ABSOLUTETIME_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.absolutetime", value: [
                    "total_user": info.total_user,
                    "total_system": info.total_system,
                    "threads_user": info.threads_user,
                    "threads_system": info.threads_system,
                ])
            } else {
                engine.reportError(module: name, key: "task.absolutetime", error: "kern_return=\(kr)")
            }
        }

        // TASK_EVENTS_INFO
        do {
            var info = task_events_info()
            var count = mach_msg_type_number_t(MemoryLayout<task_events_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(TASK_EVENTS_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.events", value: [
                    "faults": info.faults,
                    "pageins": info.pageins,
                    "cow_faults": info.cow_faults,
                    "messages_sent": info.messages_sent,
                    "messages_received": info.messages_received,
                    "syscalls_mach": info.syscalls_mach,
                    "syscalls_unix": info.syscalls_unix,
                    "csw": info.csw,
                ])
            } else {
                engine.reportError(module: name, key: "task.events", error: "kern_return=\(kr)")
            }
        }

        // TASK_FLAGS_INFO
        do {
            var info = task_flags_info()
            var count = mach_msg_type_number_t(MemoryLayout<task_flags_info>.size / MemoryLayout<natural_t>.size)
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                    task_info(task, task_flavor_t(TASK_FLAGS_INFO), intPtr, &count)
                }
            }
            if kr == KERN_SUCCESS {
                engine.report(module: name, key: "task.flags", value: ["flags": String(format: "0x%x", info.flags)])
            } else {
                engine.reportError(module: name, key: "task.flags", error: "kern_return=\(kr)")
            }
        }
    }

    // MARK: - Port Enumeration

    private func enumeratePorts(engine: ReconEngine) {
        let task = mach_task_self_
        var names: mach_port_name_array_t?
        var namesCnt: mach_msg_type_number_t = 0
        var types: mach_port_type_array_t?
        var typesCnt: mach_msg_type_number_t = 0

        let kr = mach_port_names(task, &names, &namesCnt, &types, &typesCnt)
        guard kr == KERN_SUCCESS, let names = names, let types = types else {
            engine.reportError(module: name, key: "ports", error: "mach_port_names failed: \(kr)")
            return
        }

        engine.report(module: name, key: "ports.count", value: namesCnt)

        for i in 0..<Int(namesCnt) {
            let portName = names[i]
            let portType = types[i]
            var typeStrs: [String] = []
            if portType & mach_port_type_t(MACH_PORT_TYPE_SEND) != 0 { typeStrs.append("SEND") }
            if portType & mach_port_type_t(MACH_PORT_TYPE_RECEIVE) != 0 { typeStrs.append("RECEIVE") }
            if portType & mach_port_type_t(MACH_PORT_TYPE_SEND_ONCE) != 0 { typeStrs.append("SEND_ONCE") }
            if portType & mach_port_type_t(MACH_PORT_TYPE_PORT_SET) != 0 { typeStrs.append("PORT_SET") }
            if portType & mach_port_type_t(MACH_PORT_TYPE_DEAD_NAME) != 0 { typeStrs.append("DEAD_NAME") }

            var portInfo: [String: Any] = [
                "name": String(format: "0x%x", portName),
                "type_raw": String(format: "0x%x", portType),
                "types": typeStrs,
            ]

            // Try MACH_PORT_LIMITS_INFO
            var limits = mach_port_limits()
            var limitsCount = mach_msg_type_number_t(MemoryLayout<mach_port_limits>.size / MemoryLayout<natural_t>.size)
            let limitsKR = withUnsafeMutablePointer(to: &limits) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(limitsCount)) { intPtr in
                    mach_port_get_attributes(task, portName, MACH_PORT_LIMITS_INFO, intPtr, &limitsCount)
                }
            }
            if limitsKR == KERN_SUCCESS {
                portInfo["queue_limit"] = limits.mpl_qlimit
            }

            // Try MACH_PORT_RECEIVE_STATUS (only for receive rights)
            if portType & mach_port_type_t(MACH_PORT_TYPE_RECEIVE) != 0 {
                var status = mach_port_status()
                var statusCount = mach_msg_type_number_t(MemoryLayout<mach_port_status>.size / MemoryLayout<natural_t>.size)
                let statusKR = withUnsafeMutablePointer(to: &status) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(statusCount)) { intPtr in
                        mach_port_get_attributes(task, portName, MACH_PORT_RECEIVE_STATUS, intPtr, &statusCount)
                    }
                }
                if statusKR == KERN_SUCCESS {
                    portInfo["receive_status"] = [
                        "seqno": status.mps_seqno,
                        "mscount": status.mps_mscount,
                        "qlimit": status.mps_qlimit,
                        "msgcount": status.mps_msgcount,
                        "sorights": status.mps_sorights,
                        "srights": status.mps_srights,
                    ]
                }
            }

            // Only report first 200 individually, then summarize
            if i < 200 {
                engine.report(module: name, key: "port.\(i)", value: portInfo)
            }
        }

        vm_deallocate(task, vm_address_t(bitPattern: names), vm_size_t(namesCnt) * vm_size_t(MemoryLayout<mach_port_name_t>.size))
        vm_deallocate(task, vm_address_t(bitPattern: types), vm_size_t(typesCnt) * vm_size_t(MemoryLayout<mach_port_type_t>.size))
    }

    // MARK: - Host Info

    private func collectHostInfo(engine: ReconEngine) {
        let host = mach_host_self()

        // HOST_BASIC_INFO
        var basicInfo = host_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<host_basic_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &basicInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                host_info(host, HOST_BASIC_INFO, intPtr, &count)
            }
        }
        if kr == KERN_SUCCESS {
            engine.report(module: name, key: "host.basic_info", value: [
                "max_cpus": basicInfo.max_cpus,
                "avail_cpus": basicInfo.avail_cpus,
                "memory_size": basicInfo.memory_size,
                "cpu_type": basicInfo.cpu_type,
                "cpu_subtype": basicInfo.cpu_subtype,
                "cpu_threadtype": basicInfo.cpu_threadtype,
                "physical_cpu": basicInfo.physical_cpu,
                "physical_cpu_max": basicInfo.physical_cpu_max,
                "logical_cpu": basicInfo.logical_cpu,
                "logical_cpu_max": basicInfo.logical_cpu_max,
                "max_mem": basicInfo.max_mem,
            ])
        } else {
            engine.reportError(module: name, key: "host.basic_info", error: "kern_return=\(kr)")
        }

        // HOST_SCHED_INFO
        var schedInfo = host_sched_info()
        var schedCount = mach_msg_type_number_t(MemoryLayout<host_sched_info_data_t>.size / MemoryLayout<integer_t>.size)
        let schedKR = withUnsafeMutablePointer(to: &schedInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(schedCount)) { intPtr in
                host_info(host, HOST_SCHED_INFO, intPtr, &schedCount)
            }
        }
        if schedKR == KERN_SUCCESS {
            engine.report(module: name, key: "host.sched_info", value: [
                "min_timeout": schedInfo.min_timeout,
                "min_quantum": schedInfo.min_quantum,
            ])
        } else {
            engine.reportError(module: name, key: "host.sched_info", error: "kern_return=\(schedKR)")
        }

        // HOST_PRIORITY_INFO
        var prioInfo = host_priority_info()
        var prioCount = mach_msg_type_number_t(MemoryLayout<host_priority_info_data_t>.size / MemoryLayout<integer_t>.size)
        let prioKR = withUnsafeMutablePointer(to: &prioInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(prioCount)) { intPtr in
                host_info(host, HOST_PRIORITY_INFO, intPtr, &prioCount)
            }
        }
        if prioKR == KERN_SUCCESS {
            engine.report(module: name, key: "host.priority_info", value: [
                "kernel_priority": prioInfo.kernel_priority,
                "system_priority": prioInfo.system_priority,
                "server_priority": prioInfo.server_priority,
                "user_priority": prioInfo.user_priority,
                "depress_priority": prioInfo.depress_priority,
                "idle_priority": prioInfo.idle_priority,
                "minimum_priority": prioInfo.minimum_priority,
                "maximum_priority": prioInfo.maximum_priority,
            ])
        } else {
            engine.reportError(module: name, key: "host.priority_info", error: "kern_return=\(prioKR)")
        }
    }

    // MARK: - Host Statistics

    private func collectHostStatistics(engine: ReconEngine) {
        let host = mach_host_self()

        // HOST_VM_INFO64
        var vmInfo = vm_statistics64()
        var vmCount = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let vmKR = withUnsafeMutablePointer(to: &vmInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(vmCount)) { intPtr in
                host_statistics64(host, HOST_VM_INFO64, intPtr, &vmCount)
            }
        }
        if vmKR == KERN_SUCCESS {
            engine.report(module: name, key: "host.vm_info64", value: [
                "free_count": vmInfo.free_count,
                "active_count": vmInfo.active_count,
                "inactive_count": vmInfo.inactive_count,
                "wire_count": vmInfo.wire_count,
                "zero_fill_count": vmInfo.zero_fill_count,
                "reactivations": vmInfo.reactivations,
                "pageins": vmInfo.pageins,
                "pageouts": vmInfo.pageouts,
                "faults": vmInfo.faults,
                "cow_faults": vmInfo.cow_faults,
                "lookups": vmInfo.lookups,
                "hits": vmInfo.hits,
                "purges": vmInfo.purges,
                "purgeable_count": vmInfo.purgeable_count,
                "speculative_count": vmInfo.speculative_count,
                "decompressions": vmInfo.decompressions,
                "compressions": vmInfo.compressions,
                "swapins": vmInfo.swapins,
                "swapouts": vmInfo.swapouts,
                "compressor_page_count": vmInfo.compressor_page_count,
                "throttled_count": vmInfo.throttled_count,
                "external_page_count": vmInfo.external_page_count,
                "internal_page_count": vmInfo.internal_page_count,
                "total_uncompressed_pages_in_compressor": vmInfo.total_uncompressed_pages_in_compressor,
            ])
        } else {
            engine.reportError(module: name, key: "host.vm_info64", error: "kern_return=\(vmKR)")
        }

        // HOST_CPU_LOAD_INFO
        var cpuInfo = host_cpu_load_info()
        var cpuCount = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info>.size / MemoryLayout<integer_t>.size)
        let cpuKR = withUnsafeMutablePointer(to: &cpuInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(cpuCount)) { intPtr in
                host_statistics(host, HOST_CPU_LOAD_INFO, intPtr, &cpuCount)
            }
        }
        if cpuKR == KERN_SUCCESS {
            let ticks = cpuInfo.cpu_ticks
            engine.report(module: name, key: "host.cpu_load", value: [
                "user_ticks": ticks.0,
                "system_ticks": ticks.1,
                "idle_ticks": ticks.2,
                "nice_ticks": ticks.3,
            ])
        } else {
            engine.reportError(module: name, key: "host.cpu_load", error: "kern_return=\(cpuKR)")
        }
    }

    // MARK: - Special Ports

    private func probeSpecialPorts(engine: ReconEngine) {
        let host = mach_host_self()
        for i: Int32 in 0...20 {
            var port: mach_port_t = 0
            let kr = host_get_special_port(host, HOST_LOCAL_NODE, i, &port)
            engine.report(module: name, key: "special_port.\(i)", value: [
                "result": kr == KERN_SUCCESS ? "success" : "failed",
                "kern_return": kr,
                "port": kr == KERN_SUCCESS ? String(format: "0x%x", port) : "none",
            ])
        }
    }

    // MARK: - task_for_pid

    private func probeTaskForPid(engine: ReconEngine) {
        for pid: Int32 in [0, 1, getpid()] {
            var taskPort: mach_port_t = 0
            let kr = task_for_pid(mach_task_self_, pid, &taskPort)
            engine.report(module: name, key: "task_for_pid.\(pid)", value: [
                "pid": pid,
                "result": kr == KERN_SUCCESS ? "success" : "failed",
                "kern_return": kr,
                "port": kr == KERN_SUCCESS ? String(format: "0x%x", taskPort) : "none",
            ])
        }
    }

    // MARK: - Thread Info

    private func collectThreadInfo(engine: ReconEngine) {
        let task = mach_task_self_
        var threadList: thread_act_array_t?
        var threadCount: mach_msg_type_number_t = 0

        let kr = task_threads(task, &threadList, &threadCount)
        guard kr == KERN_SUCCESS, let threads = threadList else {
            engine.reportError(module: name, key: "threads", error: "task_threads failed: \(kr)")
            return
        }

        engine.report(module: name, key: "threads.count", value: threadCount)

        for i in 0..<Int(threadCount) {
            let thread = threads[i]

            // THREAD_BASIC_INFO
            var basicInfo = thread_basic_info()
            var basicCount = mach_msg_type_number_t(THREAD_BASIC_INFO_COUNT)
            let basicKR = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { intPtr in
                    thread_info(thread, thread_flavor_t(THREAD_BASIC_INFO), intPtr, &basicCount)
                }
            }
            if basicKR == KERN_SUCCESS {
                engine.report(module: name, key: "thread.\(i).basic_info", value: [
                    "user_time_seconds": basicInfo.user_time.seconds,
                    "user_time_microseconds": basicInfo.user_time.microseconds,
                    "system_time_seconds": basicInfo.system_time.seconds,
                    "system_time_microseconds": basicInfo.system_time.microseconds,
                    "cpu_usage": basicInfo.cpu_usage,
                    "policy": basicInfo.policy,
                    "run_state": basicInfo.run_state,
                    "flags": basicInfo.flags,
                    "suspend_count": basicInfo.suspend_count,
                    "sleep_time": basicInfo.sleep_time,
                ])
            }

            // THREAD_IDENTIFIER_INFO
            var idInfo = thread_identifier_info()
            var idCount = mach_msg_type_number_t(MemoryLayout<thread_identifier_info>.size / MemoryLayout<integer_t>.size)
            let idKR = withUnsafeMutablePointer(to: &idInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(idCount)) { intPtr in
                    thread_info(thread, thread_flavor_t(THREAD_IDENTIFIER_INFO), intPtr, &idCount)
                }
            }
            if idKR == KERN_SUCCESS {
                engine.report(module: name, key: "thread.\(i).identifier_info", value: [
                    "thread_id": idInfo.thread_id,
                    "thread_handle": idInfo.thread_handle,
                    "dispatch_qaddr": String(format: "0x%llx", idInfo.dispatch_qaddr),
                ])
            }

            // Thread policy — THREAD_PRECEDENCE_POLICY
            var precedence = thread_precedence_policy()
            var precedenceCount = mach_msg_type_number_t(MemoryLayout<thread_precedence_policy>.size / MemoryLayout<integer_t>.size)
            var getDefault: boolean_t = 0
            let precKR = withUnsafeMutablePointer(to: &precedence) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(precedenceCount)) { intPtr in
                    thread_policy_get(thread, thread_policy_flavor_t(THREAD_PRECEDENCE_POLICY), intPtr, &precedenceCount, &getDefault)
                }
            }
            if precKR == KERN_SUCCESS {
                engine.report(module: name, key: "thread.\(i).precedence", value: [
                    "importance": precedence.importance,
                    "is_default": getDefault != 0,
                ])
            }

            mach_port_deallocate(task, thread)
        }

        vm_deallocate(task, vm_address_t(bitPattern: threadList), vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.size))
    }

    // MARK: - Clock Services

    private func probeClockServices(engine: ReconEngine) {
        let host = mach_host_self()
        let clockIDs: [(String, Int32)] = [
            ("REALTIME_CLOCK", REALTIME_CLOCK),
            ("CALENDAR_CLOCK", CALENDAR_CLOCK),
            ("SYSTEM_CLOCK", SYSTEM_CLOCK),
        ]
        for (clockName, clockID) in clockIDs {
            var clockPort: clock_serv_t = 0
            let kr = host_get_clock_service(host, clock_id_t(clockID), &clockPort)
            if kr == KERN_SUCCESS {
                var time = mach_timespec_t()
                let timeKR = clock_get_time(clockPort, &time)
                engine.report(module: name, key: "clock.\(clockName)", value: [
                    "available": true,
                    "port": String(format: "0x%x", clockPort),
                    "seconds": timeKR == KERN_SUCCESS ? time.tv_sec : -1,
                    "nanoseconds": timeKR == KERN_SUCCESS ? time.tv_nsec : -1,
                ])
                mach_port_deallocate(mach_task_self_, clockPort)
            } else {
                engine.report(module: name, key: "clock.\(clockName)", value: [
                    "available": false,
                    "kern_return": kr,
                ])
            }
        }
    }
}
