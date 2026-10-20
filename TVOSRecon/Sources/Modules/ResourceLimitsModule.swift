// ResourceLimitsModule.swift
// TVOSRecon
//
// Probes all POSIX resource limits, system configuration values, and
// path configuration. This reveals the exact constraints the sandbox
// and kernel impose on the app: maximum open files, stack size, memory
// limits, and whether any can be raised. Security researchers should
// look for: limits that are unusually permissive (potential oversight),
// whether hard limits can be raised (privilege escalation indicator),
// and system config values that reveal hardware/OS capabilities.

import Foundation
import Darwin

final class ResourceLimitsModule: ReconModule {
    let name = "ResourceLimits"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeResourceLimits(engine: engine)
        probeSysconf(engine: engine)
        probeConfstr(engine: engine)
    }

    // MARK: - getrlimit / setrlimit

    private func probeResourceLimits(engine: ReconEngine) {
        let resources: [(String, Int32)] = [
            ("RLIMIT_CPU", RLIMIT_CPU),
            ("RLIMIT_FSIZE", RLIMIT_FSIZE),
            ("RLIMIT_DATA", RLIMIT_DATA),
            ("RLIMIT_STACK", RLIMIT_STACK),
            ("RLIMIT_CORE", RLIMIT_CORE),
            ("RLIMIT_RSS", RLIMIT_RSS),
            ("RLIMIT_MEMLOCK", RLIMIT_MEMLOCK),
            ("RLIMIT_NPROC", RLIMIT_NPROC),
            ("RLIMIT_NOFILE", RLIMIT_NOFILE),
        ]

        for (resName, resValue) in resources {
            var limit = rlimit()
            let result = getrlimit(resValue, &limit)
            if result == 0 {
                engine.report(module: name, key: "rlimit.\(resName).softLimit",
                              value: formatRlim(limit.rlim_cur))
                engine.report(module: name, key: "rlimit.\(resName).hardLimit",
                              value: formatRlim(limit.rlim_max))

                if limit.rlim_cur < limit.rlim_max {
                    var raised = rlimit(rlim_cur: limit.rlim_max, rlim_max: limit.rlim_max)
                    let raiseResult = setrlimit(resValue, &raised)
                    engine.report(module: name, key: "rlimit.\(resName).raiseSoftToHard",
                                  value: raiseResult == 0 ? "success" : "failed (errno=\(errno))")
                    if raiseResult == 0 {
                        var restored = rlimit(rlim_cur: limit.rlim_cur, rlim_max: limit.rlim_max)
                        setrlimit(resValue, &restored)
                    }
                }

                if limit.rlim_max != rlim_t(RLIM_INFINITY) {
                    let doubled = limit.rlim_max * 2
                    var higher = rlimit(rlim_cur: doubled, rlim_max: doubled)
                    let higherResult = setrlimit(resValue, &higher)
                    engine.report(module: name, key: "rlimit.\(resName).raiseHardHigher",
                                  value: higherResult == 0 ? "success" : "failed (errno=\(errno))")
                    if higherResult == 0 {
                        var restored = rlimit(rlim_cur: limit.rlim_cur, rlim_max: limit.rlim_max)
                        setrlimit(resValue, &restored)
                    }
                }
            } else {
                engine.reportError(module: name, key: "rlimit.\(resName)", error: "getrlimit failed: errno=\(errno)")
            }
        }
    }

    private func formatRlim(_ value: rlim_t) -> String {
        if value == rlim_t(RLIM_INFINITY) {
            return "RLIM_INFINITY"
        }
        return "\(value)"
    }

    // MARK: - sysconf

    private func probeSysconf(engine: ReconEngine) {
        let scValues: [(String, Int32)] = [
            ("_SC_NPROCESSORS_CONF", _SC_NPROCESSORS_CONF),
            ("_SC_NPROCESSORS_ONLN", _SC_NPROCESSORS_ONLN),
            ("_SC_PAGESIZE", _SC_PAGESIZE),
            ("_SC_PAGE_SIZE", _SC_PAGE_SIZE),
            ("_SC_PHYS_PAGES", _SC_PHYS_PAGES),
            ("_SC_OPEN_MAX", _SC_OPEN_MAX),
            ("_SC_CHILD_MAX", _SC_CHILD_MAX),
            ("_SC_CLK_TCK", _SC_CLK_TCK),
            ("_SC_ARG_MAX", _SC_ARG_MAX),
            ("_SC_IOV_MAX", _SC_IOV_MAX),
            ("_SC_SYMLOOP_MAX", _SC_SYMLOOP_MAX),
            ("_SC_HOST_NAME_MAX", _SC_HOST_NAME_MAX),
            ("_SC_NGROUPS_MAX", _SC_NGROUPS_MAX),
            ("_SC_LINE_MAX", _SC_LINE_MAX),
            ("_SC_STREAM_MAX", _SC_STREAM_MAX),
            ("_SC_TZNAME_MAX", _SC_TZNAME_MAX),
            ("_SC_THREAD_STACK_MIN", _SC_THREAD_STACK_MIN),
            ("_SC_THREAD_THREADS_MAX", _SC_THREAD_THREADS_MAX),
            ("_SC_XOPEN_VERSION", _SC_XOPEN_VERSION),
            ("_SC_ATEXIT_MAX", _SC_ATEXIT_MAX),
            ("_SC_PASS_MAX", _SC_PASS_MAX),
            ("_SC_AIO_MAX", _SC_AIO_MAX),
            ("_SC_AIO_LISTIO_MAX", _SC_AIO_LISTIO_MAX),
            ("_SC_SIGQUEUE_MAX", _SC_SIGQUEUE_MAX),
            ("_SC_SEM_NSEMS_MAX", _SC_SEM_NSEMS_MAX),
            ("_SC_SEM_VALUE_MAX", _SC_SEM_VALUE_MAX),
            ("_SC_DELAYTIMER_MAX", _SC_DELAYTIMER_MAX),
            ("_SC_TIMER_MAX", _SC_TIMER_MAX),
            ("_SC_MQ_OPEN_MAX", _SC_MQ_OPEN_MAX),
            ("_SC_MQ_PRIO_MAX", _SC_MQ_PRIO_MAX),
            ("_SC_RTSIG_MAX", _SC_RTSIG_MAX),
            ("_SC_SPAWN", _SC_SPAWN),
            ("_SC_MEMLOCK_RANGE", _SC_MEMLOCK_RANGE),
            ("_SC_MEMORY_PROTECTION", _SC_MEMORY_PROTECTION),
            ("_SC_LOGIN_NAME_MAX", _SC_LOGIN_NAME_MAX),
            ("_SC_THREAD_DESTRUCTOR_ITERATIONS", _SC_THREAD_DESTRUCTOR_ITERATIONS),
            ("_SC_THREAD_KEYS_MAX", _SC_THREAD_KEYS_MAX),
            ("_SC_GETGR_R_SIZE_MAX", _SC_GETGR_R_SIZE_MAX),
            ("_SC_GETPW_R_SIZE_MAX", _SC_GETPW_R_SIZE_MAX),
            ("_SC_THREAD_PRIO_INHERIT", _SC_THREAD_PRIO_INHERIT),
            ("_SC_THREAD_PRIO_PROTECT", _SC_THREAD_PRIO_PROTECT),
            ("_SC_THREAD_PRIORITY_SCHEDULING", _SC_THREAD_PRIORITY_SCHEDULING),
            ("_SC_THREAD_PROCESS_SHARED", _SC_THREAD_PROCESS_SHARED),
            ("_SC_THREAD_SAFE_FUNCTIONS", _SC_THREAD_SAFE_FUNCTIONS),
            ("_SC_THREADS", _SC_THREADS),
            ("_SC_BC_BASE_MAX", _SC_BC_BASE_MAX),
            ("_SC_BC_DIM_MAX", _SC_BC_DIM_MAX),
            ("_SC_BC_SCALE_MAX", _SC_BC_SCALE_MAX),
            ("_SC_BC_STRING_MAX", _SC_BC_STRING_MAX),
            ("_SC_COLL_WEIGHTS_MAX", _SC_COLL_WEIGHTS_MAX),
            ("_SC_EXPR_NEST_MAX", _SC_EXPR_NEST_MAX),
            ("_SC_RE_DUP_MAX", _SC_RE_DUP_MAX),
            ("_SC_VERSION", _SC_VERSION),
            ("_SC_2_VERSION", _SC_2_VERSION),
            ("_SC_2_C_DEV", _SC_2_C_DEV),
            ("_SC_2_FORT_DEV", _SC_2_FORT_DEV),
            ("_SC_2_FORT_RUN", _SC_2_FORT_RUN),
            ("_SC_2_LOCALEDEF", _SC_2_LOCALEDEF),
            ("_SC_2_SW_DEV", _SC_2_SW_DEV),
            ("_SC_2_UPE", _SC_2_UPE),
            ("_SC_MAPPED_FILES", _SC_MAPPED_FILES),
            ("_SC_FSYNC", _SC_FSYNC),
            ("_SC_SHARED_MEMORY_OBJECTS", _SC_SHARED_MEMORY_OBJECTS),
            ("_SC_SYNCHRONIZED_IO", _SC_SYNCHRONIZED_IO),
            ("_SC_TIMERS", _SC_TIMERS),
            ("_SC_ASYNCHRONOUS_IO", _SC_ASYNCHRONOUS_IO),
            ("_SC_PRIORITIZED_IO", _SC_PRIORITIZED_IO),
            ("_SC_REALTIME_SIGNALS", _SC_REALTIME_SIGNALS),
            ("_SC_SEMAPHORES", _SC_SEMAPHORES),
            ("_SC_MESSAGE_PASSING", _SC_MESSAGE_PASSING),
            ("_SC_JOB_CONTROL", _SC_JOB_CONTROL),
            ("_SC_SAVED_IDS", _SC_SAVED_IDS),
            ("_SC_PRIORITY_SCHEDULING", _SC_PRIORITY_SCHEDULING),
            ("_SC_ADVISORY_INFO", _SC_ADVISORY_INFO),
            ("_SC_BARRIERS", _SC_BARRIERS),
            ("_SC_CLOCK_SELECTION", _SC_CLOCK_SELECTION),
            ("_SC_MONOTONIC_CLOCK", _SC_MONOTONIC_CLOCK),
            ("_SC_READER_WRITER_LOCKS", _SC_READER_WRITER_LOCKS),
            ("_SC_SPIN_LOCKS", _SC_SPIN_LOCKS),
            ("_SC_REGEXP", _SC_REGEXP),
            ("_SC_SHELL", _SC_SHELL),
            ("_SC_SPORADIC_SERVER", _SC_SPORADIC_SERVER),
            ("_SC_THREAD_SPORADIC_SERVER", _SC_THREAD_SPORADIC_SERVER),
            ("_SC_TIMEOUTS", _SC_TIMEOUTS),
            ("_SC_TRACE", _SC_TRACE),
            ("_SC_TRACE_EVENT_FILTER", _SC_TRACE_EVENT_FILTER),
            ("_SC_TRACE_INHERIT", _SC_TRACE_INHERIT),
            ("_SC_TRACE_LOG", _SC_TRACE_LOG),
            ("_SC_TYPED_MEMORY_OBJECTS", _SC_TYPED_MEMORY_OBJECTS),
            ("_SC_IPV6", _SC_IPV6),
            ("_SC_RAW_SOCKETS", _SC_RAW_SOCKETS),
            ("_SC_V6_ILP32_OFF32", _SC_V6_ILP32_OFF32),
            ("_SC_V6_ILP32_OFFBIG", _SC_V6_ILP32_OFFBIG),
            ("_SC_V6_LP64_OFF64", _SC_V6_LP64_OFF64),
            ("_SC_V6_LPBIG_OFFBIG", _SC_V6_LPBIG_OFFBIG),
            ("_SC_XOPEN_CRYPT", _SC_XOPEN_CRYPT),
            ("_SC_XOPEN_ENH_I18N", _SC_XOPEN_ENH_I18N),
            ("_SC_XOPEN_LEGACY", _SC_XOPEN_LEGACY),
            ("_SC_XOPEN_REALTIME", _SC_XOPEN_REALTIME),
            ("_SC_XOPEN_REALTIME_THREADS", _SC_XOPEN_REALTIME_THREADS),
            ("_SC_XOPEN_SHM", _SC_XOPEN_SHM),
            ("_SC_XOPEN_UNIX", _SC_XOPEN_UNIX),
        ]

        for (scName, scValue) in scValues {
            errno = 0
            let result = sysconf(scValue)
            if result == -1 && errno != 0 {
                engine.reportError(module: name, key: "sysconf.\(scName)",
                                   error: "errno=\(errno)")
            } else {
                engine.report(module: name, key: "sysconf.\(scName)", value: result)
            }
        }
    }

    // MARK: - confstr

    private func probeConfstr(engine: ReconEngine) {
        let confstrValues: [(String, Int32)] = [
            ("_CS_PATH", _CS_PATH),
            ("_CS_DARWIN_USER_DIR", _CS_DARWIN_USER_DIR),
            ("_CS_DARWIN_USER_TEMP_DIR", _CS_DARWIN_USER_TEMP_DIR),
            ("_CS_DARWIN_USER_CACHE_DIR", _CS_DARWIN_USER_CACHE_DIR),
        ]

        for (csName, csValue) in confstrValues {
            let size = confstr(csValue, nil, 0)
            if size > 0 {
                var buffer = [CChar](repeating: 0, count: size)
                confstr(csValue, &buffer, size)
                engine.report(module: name, key: "confstr.\(csName)", value: String(cString: buffer))
            } else {
                engine.reportError(module: name, key: "confstr.\(csName)", error: "confstr returned 0, errno=\(errno)")
            }
        }
    }
}
