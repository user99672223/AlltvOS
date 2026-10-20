// ClockAndTimersModule.swift
// Probes all available clock sources, timer resolution, and time-related syscalls.
// Reveals timing capabilities and restrictions relevant to side-channel analysis
// and precise timing attacks from the sandbox.

import Foundation
import Darwin
import QuartzCore

final class ClockAndTimersModule: ReconModule {
    let name = "ClockAndTimers"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeClockGettime(engine: engine)
        probeClockGetres(engine: engine)
        probeMachTime(engine: engine)
        probeClockSettime(engine: engine)
        probeGettimeofday(engine: engine)
        measureTimerResolution(engine: engine)
        probeCAMediaTime(engine: engine)
    }

    // MARK: - clock_gettime

    private func probeClockGettime(engine: ReconEngine) {
        let clocks: [(String, clockid_t)] = [
            ("CLOCK_REALTIME", CLOCK_REALTIME),
            ("CLOCK_MONOTONIC", CLOCK_MONOTONIC),
            ("CLOCK_MONOTONIC_RAW", CLOCK_MONOTONIC_RAW),
            ("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID),
            ("CLOCK_THREAD_CPUTIME_ID", CLOCK_THREAD_CPUTIME_ID),
            ("CLOCK_UPTIME_RAW", CLOCK_UPTIME_RAW),
            ("CLOCK_UPTIME_RAW_APPROX", clockid_t(8)),   // CLOCK_UPTIME_RAW_APPROX = 8
            ("CLOCK_MONOTONIC_RAW_APPROX", clockid_t(5)), // CLOCK_MONOTONIC_RAW_APPROX = 5
        ]

        for (label, clockId) in clocks {
            var ts = timespec()
            let ret = clock_gettime(clockId, &ts)
            if ret == 0 {
                engine.report(module: name, key: "clock_gettime_\(label)", value: [
                    "tv_sec": ts.tv_sec,
                    "tv_nsec": ts.tv_nsec,
                    "total_ns": Int64(ts.tv_sec) * 1_000_000_000 + Int64(ts.tv_nsec)
                ] as [String: Any])
            } else {
                engine.reportError(module: name, key: "clock_gettime_\(label)", error: "errno=\(errno) (\(String(cString: strerror(errno))))")
            }
        }
    }

    // MARK: - clock_getres

    private func probeClockGetres(engine: ReconEngine) {
        let clocks: [(String, clockid_t)] = [
            ("CLOCK_REALTIME", CLOCK_REALTIME),
            ("CLOCK_MONOTONIC", CLOCK_MONOTONIC),
            ("CLOCK_MONOTONIC_RAW", CLOCK_MONOTONIC_RAW),
            ("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID),
            ("CLOCK_THREAD_CPUTIME_ID", CLOCK_THREAD_CPUTIME_ID),
            ("CLOCK_UPTIME_RAW", CLOCK_UPTIME_RAW),
        ]

        for (label, clockId) in clocks {
            var res = timespec()
            let ret = clock_getres(clockId, &res)
            if ret == 0 {
                engine.report(module: name, key: "clock_getres_\(label)", value: [
                    "tv_sec": res.tv_sec,
                    "tv_nsec": res.tv_nsec,
                    "resolution_ns": Int64(res.tv_sec) * 1_000_000_000 + Int64(res.tv_nsec)
                ] as [String: Any])
            } else {
                engine.reportError(module: name, key: "clock_getres_\(label)", error: "errno=\(errno) (\(String(cString: strerror(errno))))")
            }
        }
    }

    // MARK: - Mach Time

    private func probeMachTime(engine: ReconEngine) {
        // mach_absolute_time
        let absTime = mach_absolute_time()
        engine.report(module: name, key: "mach_absolute_time", value: absTime)

        // mach_timebase_info
        var info = mach_timebase_info_data_t()
        let kr = mach_timebase_info(&info)
        engine.report(module: name, key: "mach_timebase_info", value: [
            "kr": kr,
            "numer": info.numer,
            "denom": info.denom,
            "ns_per_tick": Double(info.numer) / Double(info.denom)
        ] as [String: Any])

        // mach_continuous_time (available since macOS 10.12 / tvOS 10.0)
        let contTime = mach_continuous_time()
        engine.report(module: name, key: "mach_continuous_time", value: contTime)

        // mach_approximate_time
        let approxTime = mach_approximate_time()
        engine.report(module: name, key: "mach_approximate_time", value: approxTime)

        // Calculate wall-clock nanoseconds
        let nanosPerTick = Double(info.numer) / Double(info.denom)
        engine.report(module: name, key: "mach_absolute_time_ns", value: Double(absTime) * nanosPerTick)
        engine.report(module: name, key: "mach_continuous_time_ns", value: Double(contTime) * nanosPerTick)

        // host_get_clock_service
        let host = mach_host_self()
        let clockIds: [(String, Int32)] = [
            ("REALTIME_CLOCK", 0),    // REALTIME_CLOCK
            ("CALENDAR_CLOCK", 1),     // CALENDAR_CLOCK
            ("SYSTEM_CLOCK", 0),       // SYSTEM_CLOCK = REALTIME_CLOCK
        ]
        for (label, clockId) in clockIds {
            var clockPort: clock_serv_t = 0
            let ckr = host_get_clock_service(host, clock_id_t(clockId), &clockPort)
            if ckr == KERN_SUCCESS {
                var clockTime = mach_timespec_t()
                let readKr = clock_get_time(clockPort, &clockTime)
                engine.report(module: name, key: "clock_service_\(label)", value: [
                    "port": clockPort,
                    "read_kr": readKr,
                    "tv_sec": clockTime.tv_sec,
                    "tv_nsec": clockTime.tv_nsec
                ] as [String: Any])
                mach_port_deallocate(mach_task_self_, clockPort)
            } else {
                engine.reportError(module: name, key: "clock_service_\(label)", error: "host_get_clock_service kr=\(ckr)")
            }
        }
    }

    // MARK: - clock_settime (should fail)

    private func probeClockSettime(engine: ReconEngine) {
        let clocks: [(String, clockid_t)] = [
            ("CLOCK_REALTIME", CLOCK_REALTIME),
            ("CLOCK_MONOTONIC", CLOCK_MONOTONIC),
            ("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID),
        ]

        for (label, clockId) in clocks {
            var ts = timespec(tv_sec: 0, tv_nsec: 0)
            // Get current time first
            clock_gettime(clockId, &ts)
            // Try to set it back (no-op change)
            let ret = clock_settime(clockId, &ts)
            let err = errno
            engine.report(module: name, key: "clock_settime_\(label)", value: [
                "return": ret,
                "errno": err,
                "errno_name": String(cString: strerror(err))
            ] as [String: Any])
        }
    }

    // MARK: - gettimeofday / settimeofday

    private func probeGettimeofday(engine: ReconEngine) {
        var tv = timeval()
        var tz = timezone()
        let ret = gettimeofday(&tv, &tz)
        engine.report(module: name, key: "gettimeofday", value: [
            "return": ret,
            "tv_sec": tv.tv_sec,
            "tv_usec": tv.tv_usec,
            "tz_minuteswest": tz.tz_minuteswest,
            "tz_dsttime": tz.tz_dsttime
        ] as [String: Any])

        // settimeofday (should fail)
        let setRet = settimeofday(&tv, &tz)
        let err = errno
        engine.report(module: name, key: "settimeofday", value: [
            "return": setRet,
            "errno": err,
            "errno_name": String(cString: strerror(err))
        ] as [String: Any])

        // adjtime (should fail)
        var delta = timeval(tv_sec: 0, tv_usec: 1)
        var oldDelta = timeval()
        let adjRet = adjtime(&delta, &oldDelta)
        let adjErr = errno
        engine.report(module: name, key: "adjtime", value: [
            "return": adjRet,
            "errno": adjErr,
            "errno_name": String(cString: strerror(adjErr))
        ] as [String: Any])
    }

    // MARK: - Empirical Timer Resolution

    private func measureTimerResolution(engine: ReconEngine) {
        // Measure with clock_gettime CLOCK_MONOTONIC_RAW
        var minDelta: UInt64 = UInt64.max
        let iterations = 10000
        var prev = timespec()
        clock_gettime(CLOCK_MONOTONIC_RAW, &prev)

        for _ in 0..<iterations {
            var now = timespec()
            clock_gettime(CLOCK_MONOTONIC_RAW, &now)
            let deltaNs = UInt64(now.tv_sec - prev.tv_sec) * 1_000_000_000 + UInt64(now.tv_nsec - prev.tv_nsec)
            if deltaNs > 0 && deltaNs < minDelta {
                minDelta = deltaNs
            }
            prev = now
        }
        engine.report(module: name, key: "empirical_resolution_MONOTONIC_RAW_ns", value: minDelta == UInt64.max ? -1 : Int64(minDelta))

        // Measure with mach_absolute_time
        var machMinDelta: UInt64 = UInt64.max
        var machPrev = mach_absolute_time()
        for _ in 0..<iterations {
            let machNow = mach_absolute_time()
            let d = machNow - machPrev
            if d > 0 && d < machMinDelta {
                machMinDelta = d
            }
            machPrev = machNow
        }
        var tbInfo = mach_timebase_info_data_t()
        mach_timebase_info(&tbInfo)
        let machMinNs = machMinDelta * UInt64(tbInfo.numer) / UInt64(tbInfo.denom)
        engine.report(module: name, key: "empirical_resolution_mach_absolute_ticks", value: machMinDelta == UInt64.max ? -1 : Int64(machMinDelta))
        engine.report(module: name, key: "empirical_resolution_mach_absolute_ns", value: machMinDelta == UInt64.max ? -1 : Int64(machMinNs))

        // Measure with CLOCK_UPTIME_RAW
        minDelta = UInt64.max
        clock_gettime(CLOCK_UPTIME_RAW, &prev)
        for _ in 0..<iterations {
            var now = timespec()
            clock_gettime(CLOCK_UPTIME_RAW, &now)
            let deltaNs = UInt64(now.tv_sec - prev.tv_sec) * 1_000_000_000 + UInt64(now.tv_nsec - prev.tv_nsec)
            if deltaNs > 0 && deltaNs < minDelta {
                minDelta = deltaNs
            }
            prev = now
        }
        engine.report(module: name, key: "empirical_resolution_UPTIME_RAW_ns", value: minDelta == UInt64.max ? -1 : Int64(minDelta))
    }

    // MARK: - CACurrentMediaTime

    private func probeCAMediaTime(engine: ReconEngine) {
        let mediaTime = CACurrentMediaTime()
        engine.report(module: name, key: "CACurrentMediaTime", value: mediaTime)

        // Measure resolution of CACurrentMediaTime
        var minDelta: Double = .greatestFiniteMagnitude
        var prevT = CACurrentMediaTime()
        for _ in 0..<10000 {
            let now = CACurrentMediaTime()
            let d = now - prevT
            if d > 0 && d < minDelta {
                minDelta = d
            }
            prevT = now
        }
        engine.report(module: name, key: "CACurrentMediaTime_empirical_resolution_sec", value: minDelta)
    }
}
