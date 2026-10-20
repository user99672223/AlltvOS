// ProcessEnumerationModule.swift
// TVOSRecon
//
// Enumerates running processes, file descriptors, and credential info.
// On tvOS, sandbox restrictions heavily limit what process information is
// visible. Security researchers should look for: whether proc_listallpids
// reveals other processes (indicating sandbox escape potential), which
// file descriptors are open (revealing IPC channels), and what credential
// context the app runs under (uid/gid determines privilege level).

import Foundation
import Darwin

final class ProcessEnumerationModule: ReconModule {
    let name = "ProcessEnumeration"
    let timeout: TimeInterval = 90

    func run(engine: ReconEngine) {
        dumpCredentials(engine: engine)
        enumerateProcesses(engine: engine)
        enumerateOwnFileDescriptors(engine: engine)
        dumpResourceUsage(engine: engine)
    }

    // MARK: - Credentials

    private func dumpCredentials(engine: ReconEngine) {
        engine.report(module: name, key: "credentials.uid", value: getuid())
        engine.report(module: name, key: "credentials.euid", value: geteuid())
        engine.report(module: name, key: "credentials.gid", value: getgid())
        engine.report(module: name, key: "credentials.egid", value: getegid())
        engine.report(module: name, key: "credentials.pid", value: getpid())
        engine.report(module: name, key: "credentials.ppid", value: getppid())
        engine.report(module: name, key: "credentials.sid", value: getsid(0))
        engine.report(module: name, key: "credentials.pgrp", value: getpgrp())

        if let login = getlogin() {
            engine.report(module: name, key: "credentials.login", value: String(cString: login))
        } else {
            engine.report(module: name, key: "credentials.login", value: "nil (errno=\(errno))")
        }

        var groups = [gid_t](repeating: 0, count: 64)
        let ngroups = getgroups(64, &groups)
        if ngroups >= 0 {
            let groupList = (0..<Int(ngroups)).map { String(groups[$0]) }
            engine.report(module: name, key: "credentials.groups", value: groupList.joined(separator: ", "))
            engine.report(module: name, key: "credentials.ngroups", value: ngroups)
        } else {
            engine.reportError(module: name, key: "credentials.groups", error: "getgroups failed: errno=\(errno)")
        }

        let oldUmask = umask(0o022)
        umask(oldUmask)
        engine.report(module: name, key: "credentials.umask", value: String(format: "0o%03o", oldUmask))

        var auditInfo = auditinfo_addr_t()
        let auditResult = getaudit_addr(&auditInfo, CInt(MemoryLayout<auditinfo_addr_t>.size))
        if auditResult == 0 {
            engine.report(module: name, key: "credentials.audit.auid", value: auditInfo.ai_auid)
            engine.report(module: name, key: "credentials.audit.asid", value: auditInfo.ai_asid)
            engine.report(module: name, key: "credentials.audit.flags", value: String(format: "0x%x", auditInfo.ai_flags))
        } else {
            engine.reportError(module: name, key: "credentials.audit", error: "getaudit_addr failed: errno=\(errno)")
        }
    }

    // MARK: - Process Enumeration

    private func enumerateProcesses(engine: ReconEngine) {
        let bufSize = proc_listallpids(nil, 0)
        guard bufSize > 0 else {
            engine.reportError(module: name, key: "processes.listall", error: "proc_listallpids returned \(bufSize), errno=\(errno)")
            return
        }

        let pidCount = Int(bufSize) / MemoryLayout<pid_t>.size
        var pids = [pid_t](repeating: 0, count: pidCount + 64)
        let actualSize = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))

        guard actualSize > 0 else {
            engine.reportError(module: name, key: "processes.listall", error: "proc_listallpids second call returned \(actualSize)")
            return
        }

        let actualCount = Int(actualSize) / MemoryLayout<pid_t>.size
        engine.report(module: name, key: "processes.totalCount", value: actualCount)

        let myPid = getpid()

        for i in 0..<actualCount {
            let pid = pids[i]
            guard pid > 0 else { continue }

            let prefix = "process[\(pid)]"

            var nameBuffer = [CChar](repeating: 0, count: 256)
            let nameLen = proc_name(pid, &nameBuffer, UInt32(nameBuffer.count))
            if nameLen > 0 {
                engine.report(module: name, key: "\(prefix).name", value: String(cString: nameBuffer))
            }

            var pathBuffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
            let pathLen = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
            if pathLen > 0 {
                engine.report(module: name, key: "\(prefix).path", value: String(cString: pathBuffer))
            }

            var bsdInfo = proc_bsdinfo()
            let bsdSize = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, Int32(MemoryLayout<proc_bsdinfo>.size))
            if bsdSize == Int32(MemoryLayout<proc_bsdinfo>.size) {
                engine.report(module: name, key: "\(prefix).ppid", value: bsdInfo.pbi_ppid)
                engine.report(module: name, key: "\(prefix).uid", value: bsdInfo.pbi_uid)
                engine.report(module: name, key: "\(prefix).gid", value: bsdInfo.pbi_gid)
                engine.report(module: name, key: "\(prefix).ruid", value: bsdInfo.pbi_ruid)
                engine.report(module: name, key: "\(prefix).rgid", value: bsdInfo.pbi_rgid)
                engine.report(module: name, key: "\(prefix).svuid", value: bsdInfo.pbi_svuid)
                engine.report(module: name, key: "\(prefix).svgid", value: bsdInfo.pbi_svgid)
                engine.report(module: name, key: "\(prefix).nice", value: bsdInfo.pbi_nice)
                engine.report(module: name, key: "\(prefix).status", value: String(format: "0x%x", bsdInfo.pbi_status))
                engine.report(module: name, key: "\(prefix).flags", value: String(format: "0x%x", bsdInfo.pbi_flags))
                engine.report(module: name, key: "\(prefix).startTime",
                              value: "\(bsdInfo.pbi_start_tvsec).\(bsdInfo.pbi_start_tvusec)")
                let comm = withUnsafePointer(to: bsdInfo.pbi_comm) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMLEN)) {
                        String(cString: $0)
                    }
                }
                if !comm.isEmpty {
                    engine.report(module: name, key: "\(prefix).comm", value: comm)
                }
            } else if bsdSize < 0 {
                engine.reportError(module: name, key: "\(prefix).bsdinfo",
                                   error: "proc_pidinfo BSDINFO failed: errno=\(errno)")
            }

            var taskInfo = proc_taskinfo()
            let taskSize = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskInfo, Int32(MemoryLayout<proc_taskinfo>.size))
            if taskSize == Int32(MemoryLayout<proc_taskinfo>.size) {
                engine.report(module: name, key: "\(prefix).virtualSize", value: taskInfo.pti_virtual_size)
                engine.report(module: name, key: "\(prefix).residentSize", value: taskInfo.pti_resident_size)
                engine.report(module: name, key: "\(prefix).totalUserTime", value: taskInfo.pti_total_user)
                engine.report(module: name, key: "\(prefix).totalSystemTime", value: taskInfo.pti_total_system)
                engine.report(module: name, key: "\(prefix).threadCount", value: taskInfo.pti_threadnum)
                engine.report(module: name, key: "\(prefix).faults", value: taskInfo.pti_faults)
                engine.report(module: name, key: "\(prefix).pageins", value: taskInfo.pti_pageins)
                engine.report(module: name, key: "\(prefix).cowFaults", value: taskInfo.pti_cow_faults)
                engine.report(module: name, key: "\(prefix).messagesReceived", value: taskInfo.pti_messages_received)
                engine.report(module: name, key: "\(prefix).messagesSent", value: taskInfo.pti_messages_sent)
                engine.report(module: name, key: "\(prefix).syscallsUnix", value: taskInfo.pti_syscalls_unix)
                engine.report(module: name, key: "\(prefix).syscallsMach", value: taskInfo.pti_syscalls_mach)
                engine.report(module: name, key: "\(prefix).csw", value: taskInfo.pti_csw)
                engine.report(module: name, key: "\(prefix).policy", value: taskInfo.pti_policy)
                engine.report(module: name, key: "\(prefix).priority", value: taskInfo.pti_priority)
            }

            if pid != myPid {
                var fdBuf = [proc_fdinfo](repeating: proc_fdinfo(), count: 1)
                let otherFdSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fdBuf, Int32(MemoryLayout<proc_fdinfo>.size))
                if otherFdSize > 0 {
                    engine.report(module: name, key: "\(prefix).fdProbe", value: "accessible (size=\(otherFdSize))")
                } else {
                    engine.report(module: name, key: "\(prefix).fdProbe", value: "denied (errno=\(errno))")
                }
            }
        }
    }

    // MARK: - Own File Descriptors

    private func enumerateOwnFileDescriptors(engine: ReconEngine) {
        let pid = getpid()
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else {
            engine.reportError(module: name, key: "ownFDs", error: "PROC_PIDLISTFDS sizing returned \(bufSize)")
            return
        }

        let fdCount = Int(bufSize) / MemoryLayout<proc_fdinfo>.size
        var fdInfos = [proc_fdinfo](repeating: proc_fdinfo(), count: fdCount + 16)
        let actualSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &fdInfos,
                                       Int32(fdInfos.count * MemoryLayout<proc_fdinfo>.size))
        guard actualSize > 0 else {
            engine.reportError(module: name, key: "ownFDs", error: "PROC_PIDLISTFDS data returned \(actualSize)")
            return
        }

        let actualCount = Int(actualSize) / MemoryLayout<proc_fdinfo>.size
        engine.report(module: name, key: "ownFDs.count", value: actualCount)

        for i in 0..<actualCount {
            let fd = fdInfos[i]
            let prefix = "ownFD[\(fd.proc_fd)]"
            let typeStr = fdTypeString(fd.proc_fdtype)
            engine.report(module: name, key: "\(prefix).type", value: typeStr)

            switch fd.proc_fdtype {
            case UInt32(PROX_FDTYPE_VNODE):
                var vnodeInfo = vnode_fdinfowithpath()
                let sz = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO,
                                         &vnodeInfo, Int32(MemoryLayout<vnode_fdinfowithpath>.size))
                if sz > 0 {
                    let path = withUnsafePointer(to: vnodeInfo.pvip.vip_path) { ptr in
                        ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                            String(cString: $0)
                        }
                    }
                    engine.report(module: name, key: "\(prefix).path", value: path)
                    engine.report(module: name, key: "\(prefix).vnodeType", value: vnodeInfo.pfi.fi_openflags)
                }
            case UInt32(PROX_FDTYPE_SOCKET):
                var socketInfo = socket_fdinfo()
                let sz = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO,
                                         &socketInfo, Int32(MemoryLayout<socket_fdinfo>.size))
                if sz > 0 {
                    engine.report(module: name, key: "\(prefix).socketFamily",
                                  value: socketInfo.psi.soi_family)
                    engine.report(module: name, key: "\(prefix).socketType",
                                  value: socketInfo.psi.soi_type)
                    engine.report(module: name, key: "\(prefix).socketProtocol",
                                  value: socketInfo.psi.soi_protocol)
                }
            case UInt32(PROX_FDTYPE_PIPE):
                var pipeInfo = pipe_fdinfo()
                let sz = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDPIPEINFO,
                                         &pipeInfo, Int32(MemoryLayout<pipe_fdinfo>.size))
                if sz > 0 {
                    engine.report(module: name, key: "\(prefix).pipeStatus",
                                  value: pipeInfo.pipeinfo.pipe_status)
                    engine.report(module: name, key: "\(prefix).pipeBufferSize",
                                  value: pipeInfo.pipeinfo.pipe_peercount)
                }
            default:
                break
            }
        }
    }

    private func fdTypeString(_ fdtype: UInt32) -> String {
        switch fdtype {
        case UInt32(PROX_FDTYPE_ATALK): return "ATALK"
        case UInt32(PROX_FDTYPE_VNODE): return "VNODE"
        case UInt32(PROX_FDTYPE_SOCKET): return "SOCKET"
        case UInt32(PROX_FDTYPE_PSHM): return "PSHM"
        case UInt32(PROX_FDTYPE_PSEM): return "PSEM"
        case UInt32(PROX_FDTYPE_KQUEUE): return "KQUEUE"
        case UInt32(PROX_FDTYPE_PIPE): return "PIPE"
        case UInt32(PROX_FDTYPE_FSEVENTS): return "FSEVENTS"
        case UInt32(PROX_FDTYPE_NETPOLICY): return "NETPOLICY"
        default: return "UNKNOWN(\(fdtype))"
        }
    }

    // MARK: - Resource Usage

    private func dumpResourceUsage(engine: ReconEngine) {
        let selfPriority = getpriority(PRIO_PROCESS, 0)
        engine.report(module: name, key: "resourceUsage.selfPriority", value: selfPriority)
        if selfPriority == -1 && errno != 0 {
            engine.reportError(module: name, key: "resourceUsage.selfPriority.error", error: "errno=\(errno)")
        }

        var rusageSelf = rusage()
        if getrusage(RUSAGE_SELF, &rusageSelf) == 0 {
            engine.report(module: name, key: "resourceUsage.self.userTime",
                          value: "\(rusageSelf.ru_utime.tv_sec).\(String(format: "%06d", rusageSelf.ru_utime.tv_usec))")
            engine.report(module: name, key: "resourceUsage.self.systemTime",
                          value: "\(rusageSelf.ru_stime.tv_sec).\(String(format: "%06d", rusageSelf.ru_stime.tv_usec))")
            engine.report(module: name, key: "resourceUsage.self.maxRSS", value: rusageSelf.ru_maxrss)
            engine.report(module: name, key: "resourceUsage.self.ixrss", value: rusageSelf.ru_ixrss)
            engine.report(module: name, key: "resourceUsage.self.idrss", value: rusageSelf.ru_idrss)
            engine.report(module: name, key: "resourceUsage.self.isrss", value: rusageSelf.ru_isrss)
            engine.report(module: name, key: "resourceUsage.self.minFaults", value: rusageSelf.ru_minflt)
            engine.report(module: name, key: "resourceUsage.self.majFaults", value: rusageSelf.ru_majflt)
            engine.report(module: name, key: "resourceUsage.self.swaps", value: rusageSelf.ru_nswap)
            engine.report(module: name, key: "resourceUsage.self.blockInputOps", value: rusageSelf.ru_inblock)
            engine.report(module: name, key: "resourceUsage.self.blockOutputOps", value: rusageSelf.ru_oublock)
            engine.report(module: name, key: "resourceUsage.self.msgSent", value: rusageSelf.ru_msgsnd)
            engine.report(module: name, key: "resourceUsage.self.msgRecv", value: rusageSelf.ru_msgrcv)
            engine.report(module: name, key: "resourceUsage.self.signals", value: rusageSelf.ru_nsignals)
            engine.report(module: name, key: "resourceUsage.self.voluntaryCSW", value: rusageSelf.ru_nvcsw)
            engine.report(module: name, key: "resourceUsage.self.involuntaryCSW", value: rusageSelf.ru_nivcsw)
        } else {
            engine.reportError(module: name, key: "resourceUsage.self", error: "getrusage SELF failed: errno=\(errno)")
        }

        var rusageChildren = rusage()
        if getrusage(RUSAGE_CHILDREN, &rusageChildren) == 0 {
            engine.report(module: name, key: "resourceUsage.children.userTime",
                          value: "\(rusageChildren.ru_utime.tv_sec).\(String(format: "%06d", rusageChildren.ru_utime.tv_usec))")
            engine.report(module: name, key: "resourceUsage.children.systemTime",
                          value: "\(rusageChildren.ru_stime.tv_sec).\(String(format: "%06d", rusageChildren.ru_stime.tv_usec))")
            engine.report(module: name, key: "resourceUsage.children.maxRSS", value: rusageChildren.ru_maxrss)
        } else {
            engine.reportError(module: name, key: "resourceUsage.children", error: "getrusage CHILDREN failed: errno=\(errno)")
        }
    }
}
