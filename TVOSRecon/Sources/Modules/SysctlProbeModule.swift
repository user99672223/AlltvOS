// SysctlProbeModule.swift
// Enumerates sysctl values by walking the MIB tree and reading named keys.
// Reveals kernel configuration, hardware topology, memory layout, and
// network stack parameters — many of which leak device identity and
// security posture even inside a sandbox.

import Foundation

final class SysctlProbeModule: ReconModule {
    let name = "SysctlProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        readNamedKeys(engine: engine)
        walkMIBTree(engine: engine)
    }

    // MARK: - Read sysctl by name

    private func sysctlStringByName(_ key: String) -> String? {
        var size: size_t = 0
        guard sysctlbyname(key, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(key, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    private func sysctlIntByName(_ key: String) -> Int64? {
        var val: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(key, &val, &size, nil, 0) == 0 else { return nil }
        return val
    }

    private func sysctlUInt64ByName(_ key: String) -> UInt64? {
        var val: UInt64 = 0
        var size = MemoryLayout<UInt64>.size
        guard sysctlbyname(key, &val, &size, nil, 0) == 0 else { return nil }
        return val
    }

    private func sysctlInt32ByName(_ key: String) -> Int32? {
        var val: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(key, &val, &size, nil, 0) == 0 else { return nil }
        return val
    }

    private func readKey(_ key: String, engine: ReconEngine) {
        // Try string first
        if let s = sysctlStringByName(key) {
            engine.report(module: name, key: "sysctl.\(key)", value: s)
            return
        }
        // Try int64
        if let v = sysctlIntByName(key) {
            engine.report(module: name, key: "sysctl.\(key)", value: v)
            return
        }
        // Try raw bytes
        var size: size_t = 0
        if sysctlbyname(key, nil, &size, nil, 0) == 0, size > 0 {
            var buf = [UInt8](repeating: 0, count: size)
            if sysctlbyname(key, &buf, &size, nil, 0) == 0 {
                let hex = buf.prefix(size).map { String(format: "%02x", $0) }.joined()
                engine.report(module: name, key: "sysctl.\(key)", value: "raw[\(size)]:\(hex)")
                return
            }
        }
        let err = errno
        engine.reportError(module: name, key: "sysctl.\(key)", error: "errno=\(err) (\(String(cString: strerror(err))))")
    }

    private func readNamedKeys(engine: ReconEngine) {
        let hwKeys = [
            "hw.machine", "hw.model", "hw.ncpu", "hw.physmem", "hw.usermem",
            "hw.pagesize", "hw.cachelinesize", "hw.l1icachesize", "hw.l1dcachesize",
            "hw.l2cachesize", "hw.tbfrequency", "hw.memsize", "hw.availcpu", "hw.activecpu",
            "hw.byteorder", "hw.cpufrequency", "hw.cpufrequency_max", "hw.cpufrequency_min",
            "hw.busfrequency", "hw.busfrequency_max", "hw.busfrequency_min",
            "hw.cputype", "hw.cpusubtype", "hw.cpufamily",
            "hw.packages", "hw.logicalcpu", "hw.logicalcpu_max",
            "hw.physicalcpu", "hw.physicalcpu_max",
            "hw.optional.arm.FEAT_FlagM", "hw.optional.arm.FEAT_FlagM2",
            "hw.optional.arm.FEAT_FHM", "hw.optional.arm.FEAT_DotProd",
            "hw.optional.arm.FEAT_SHA3", "hw.optional.arm.FEAT_SHA512",
            "hw.optional.arm.FEAT_SHA256", "hw.optional.arm.FEAT_SHA1",
            "hw.optional.arm.FEAT_AES", "hw.optional.arm.FEAT_PMULL",
            "hw.optional.arm.FEAT_SPECRES", "hw.optional.arm.FEAT_SB",
            "hw.optional.arm.FEAT_FRINTTS", "hw.optional.arm.FEAT_LRCPC",
            "hw.optional.arm.FEAT_LRCPC2", "hw.optional.arm.FEAT_FCMA",
            "hw.optional.arm.FEAT_JSCVT", "hw.optional.arm.FEAT_DPB",
            "hw.optional.arm.FEAT_DPB2", "hw.optional.arm.FEAT_BF16",
            "hw.optional.arm.FEAT_I8MM", "hw.optional.arm.FEAT_BTI",
            "hw.optional.arm.FEAT_ECV", "hw.optional.arm.FEAT_LSE",
            "hw.optional.arm.FEAT_LSE2", "hw.optional.arm.FEAT_CSV2",
            "hw.optional.arm.FEAT_CSV3",
            "hw.optional.neon", "hw.optional.neon_hpfp", "hw.optional.neon_fp16",
            "hw.optional.armv8_crc32", "hw.optional.armv8_1_atomics",
            "hw.optional.armv8_2_fhm", "hw.optional.armv8_2_sha512",
            "hw.optional.armv8_2_sha3",
            "hw.optional.amx_version",
            "hw.perflevel0.physicalcpu", "hw.perflevel0.logicalcpu",
            "hw.perflevel0.cpusperl2", "hw.perflevel0.l2cachesize",
            "hw.perflevel1.physicalcpu", "hw.perflevel1.logicalcpu",
            "hw.perflevel1.cpusperl2", "hw.perflevel1.l2cachesize",
            "hw.nperflevels",
            "hw.targettype",
        ]
        for k in hwKeys { readKey(k, engine: engine) }

        let kernKeys = [
            "kern.ostype", "kern.osrelease", "kern.osversion", "kern.version",
            "kern.boottime", "kern.hostname", "kern.maxproc", "kern.maxfiles",
            "kern.securelevel", "kern.bootargs", "kern.uuid",
            "kern.maxvnodes", "kern.maxfilesperproc", "kern.safeboot",
            "kern.singleuser", "kern.corefile", "kern.sugid_coredump",
            "kern.usrstack", "kern.usrstack64",
            "kern.aiomax", "kern.aioprocmax", "kern.aiothreads",
            "kern.osproductversion", "kern.osreleasetype",
            "kern.iossupportversion", "kern.osvariant_status",
            "kern.bootobjectspath", "kern.bootsessionuuid",
            "kern.kerneldebug_boot_arg",
            "kern.monotonicclock_usecs",
            "kern.waketime", "kern.willshutdown", "kern.progressmeterenable",
            "kern.hibernatefile", "kern.hibernatemode",
            "kern.ngroups", "kern.job_control", "kern.saved_ids",
            "kern.num_files", "kern.num_vnodes", "kern.num_tasks", "kern.num_threads",
            "kern.coredump", "kern.sugid_scripts", "kern.procname",
            "kern.speculative_reads_disabled", "kern.posix1version",
            "kern.tty.ptmx_max", "kern.rage_vnode",
        ]
        for k in kernKeys { readKey(k, engine: engine) }

        let machdepKeys = [
            "machdep.cpu.brand_string", "machdep.cpu.vendor",
            "machdep.cpu.family", "machdep.cpu.model", "machdep.cpu.stepping",
            "machdep.cpu.feature_bits", "machdep.cpu.extfeature_bits",
            "machdep.cpu.core_count", "machdep.cpu.thread_count",
            "machdep.cpu.cores_per_package", "machdep.cpu.logical_per_package",
            "machdep.cpu.microcode_version",
            "machdep.cpu.cache.L2_associativity", "machdep.cpu.cache.linesize",
            "machdep.cpu.cache.size",
        ]
        for k in machdepKeys { readKey(k, engine: engine) }

        let vmKeys = [
            "vm.swapusage", "vm.loadavg",
            "vm.page_free_wanted", "vm.page_purgeable_count",
            "vm.page_purged_count", "vm.page_reusable_count",
            "vm.pages", "vm.page_free_count", "vm.page_active_count",
            "vm.page_inactive_count", "vm.page_wire_count",
            "vm.page_speculative_count", "vm.page_throttled_count",
            "vm.page_pageable_internal_count", "vm.page_pageable_external_count",
            "vm.compressor_page_count", "vm.compressor_mode",
            "vm.swapfileprefix", "vm.cs_force_kill", "vm.cs_force_hard",
            "vm.cs_debug", "vm.cs_all_vnodes", "vm.cs_enforcement",
            "vm.cs_enforcement_panic",
        ]
        for k in vmKeys { readKey(k, engine: engine) }

        let netKeys = [
            "net.inet.ip.forwarding", "net.inet.ip.ttl",
            "net.inet.ip.portrange.first", "net.inet.ip.portrange.last",
            "net.inet.ip.portrange.hifirst", "net.inet.ip.portrange.hilast",
            "net.inet.tcp.mssdflt", "net.inet.tcp.keepidle",
            "net.inet.tcp.keepintvl", "net.inet.tcp.keepinit",
            "net.inet.tcp.keepcnt", "net.inet.tcp.msl",
            "net.inet.tcp.v6mssdflt", "net.inet.tcp.sendspace",
            "net.inet.tcp.recvspace", "net.inet.tcp.always_keepalive",
            "net.inet.tcp.delayed_ack", "net.inet.tcp.log_in_vain",
            "net.inet.tcp.blackhole", "net.inet.tcp.tcp_lq_overflow",
            "net.inet.tcp.rfc1323", "net.inet.tcp.rfc3390",
            "net.inet.tcp.sack", "net.inet.tcp.sack_globalholes",
            "net.inet.tcp.ecn_initiate_out", "net.inet.tcp.ecn_negotiate_in",
            "net.inet.udp.maxdgram", "net.inet.udp.recvspace",
            "net.inet.udp.checksum", "net.inet.udp.log_in_vain",
            "net.inet.udp.blackhole",
            "net.inet6.ip6.forwarding", "net.inet6.ip6.hlim",
            "net.inet6.ip6.auto_linklocal", "net.inet6.ip6.prefer_tempaddr",
            "net.inet6.ip6.use_tempaddr", "net.inet6.ip6.temppltime",
            "net.inet6.ip6.tempvltime",
            "net.inet6.icmp6.rediraccept", "net.inet6.icmp6.nd6_maxnudhint",
            "net.local.stream.sendspace", "net.local.stream.recvspace",
            "net.local.dgram.maxdgram", "net.local.dgram.recvspace",
        ]
        for k in netKeys { readKey(k, engine: engine) }

        // Security/debug keys
        let secKeys = [
            "security.mac.sandbox.sentinel",
            "security.mac.amfi.trust_cache_status",
            "security.mac.proc_enforce", "security.mac.vnode_enforce",
            "debug.iokit_statistics", "debug.iotrace",
        ]
        for k in secKeys { readKey(k, engine: engine) }
    }

    // MARK: - Walk MIB tree by numeric OID

    private func walkMIBTree(engine: ReconEngine) {
        for topLevel in 0...15 {
            walkOID(mib: [Int32(topLevel)], depth: 0, maxDepth: 3, engine: engine)
        }
    }

    private func walkOID(mib: [Int32], depth: Int, maxDepth: Int, engine: ReconEngine) {
        guard depth <= maxDepth else { return }

        // Try to read a name for this OID using the undocumented sysctl name lookup
        var nameMib: [Int32] = [0, 3] + mib // CTL_SYSCTL, SYSCTL_NAME
        var nameBuf = [CChar](repeating: 0, count: 256)
        var nameLen: size_t = 256
        let nameResult = sysctl(&nameMib, UInt32(nameMib.count), &nameBuf, &nameLen, nil, 0)
        let oidName: String
        if nameResult == 0, nameLen > 0 {
            oidName = String(cString: nameBuf)
        } else {
            oidName = mib.map { String($0) }.joined(separator: ".")
        }

        // Try to read value
        var mibCopy = mib
        var size: size_t = 0
        let rc = sysctl(&mibCopy, UInt32(mibCopy.count), nil, &size, nil, 0)
        if rc == 0, size > 0, size < 65536 {
            var buf = [UInt8](repeating: 0, count: size)
            let rc2 = sysctl(&mibCopy, UInt32(mibCopy.count), &buf, &size, nil, 0)
            if rc2 == 0 {
                let val: String
                if size <= 8 {
                    // Likely an integer
                    var intVal: UInt64 = 0
                    memcpy(&intVal, buf, min(size, 8))
                    val = "\(intVal)"
                } else if buf.allSatisfy({ $0 >= 0x20 && $0 < 0x7F || $0 == 0 }) {
                    val = String(cString: buf)
                } else {
                    val = "raw[\(size)]:" + buf.prefix(min(size, 64)).map { String(format: "%02x", $0) }.joined()
                }
                engine.report(module: name, key: "mib.\(oidName)", value: val)
            }
        } else if rc != 0 && errno != ENOENT && errno != EISDIR {
            // Only report non-trivial errors
            if errno != ENOENT {
                engine.reportError(module: name, key: "mib.\(oidName)", error: "errno=\(errno)")
            }
        }

        // Try to recurse into children using the "next" OID mechanism
        if depth < maxDepth {
            // Use sysctl OID 0,2 (CTL_SYSCTL, SYSCTL_NEXT) to find next OID after this one
            var nextMib: [Int32] = [0, 2] + mib
            var nextOID = [Int32](repeating: 0, count: Int(CTL_MAXNAME))
            var nextLen: size_t = MemoryLayout<Int32>.size * Int(CTL_MAXNAME)
            let nextResult = sysctl(&nextMib, UInt32(nextMib.count), &nextOID, &nextLen, nil, 0)
            if nextResult == 0 {
                let count = nextLen / MemoryLayout<Int32>.size
                if count > mib.count {
                    let nextArray = Array(nextOID.prefix(count))
                    // Only recurse if next is a child of current
                    let isChild = mib.count < count && Array(nextArray.prefix(mib.count)) == mib
                    if isChild {
                        walkOID(mib: nextArray, depth: depth + 1, maxDepth: maxDepth, engine: engine)
                    }
                }
            }

            // Also try direct child enumeration
            for child in Int32(0)...Int32(32) {
                let childMib = mib + [child]
                var childMibCopy = childMib
                var testSize: size_t = 0
                let testResult = sysctl(&childMibCopy, UInt32(childMibCopy.count), nil, &testSize, nil, 0)
                if testResult == 0 || (testResult != 0 && errno == EISDIR) {
                    walkOID(mib: childMib, depth: depth + 1, maxDepth: maxDepth, engine: engine)
                }
            }
        }
    }
}
