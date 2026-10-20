// OSLogProbeModule.swift
// Probes system log access: OSLogStore, ASL, direct log file reads.
// Reveals what diagnostic and security logging information is visible
// from the sandbox — useful for understanding what the system records
// about app behavior and what an attacker could learn.

import Foundation
import os
import Darwin

final class OSLogProbeModule: ReconModule {
    let name = "OSLogProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        probeOSLogStore(engine: engine)
        probeLogFiles(engine: engine)
        probeASL(engine: engine)
        probeOSLogEnabled(engine: engine)
    }

    // MARK: - OSLogStore

    private func probeOSLogStore(engine: ReconEngine) {
        if #available(tvOS 15.0, *) {
            do {
                let store = try OSLogStore(scope: .currentProcessIdentifier)
                engine.report(module: name, key: "oslogstore_current_process", value: "accessible")

                let now = Date()
                let oneMinuteAgo = now.addingTimeInterval(-60)
                let position = store.position(date: oneMinuteAgo)

                let entries = try store.getEntries(at: position)
                var count = 0
                var interestingEntries: [[String: Any]] = []
                let interestingSubsystems = Set(["com.apple.sandbox", "com.apple.kernel", "com.apple.security", "com.apple.xpc", "com.apple.launchd"])

                for entry in entries {
                    count += 1
                    if count > 200 { break }

                    if let logEntry = entry as? OSLogEntryLog {
                        let entryDict: [String: Any] = [
                            "timestamp": logEntry.date.timeIntervalSince1970,
                            "subsystem": logEntry.subsystem,
                            "category": logEntry.category,
                            "composedMessage": String(logEntry.composedMessage.prefix(256)),
                            "level": logLevelString(logEntry.level),
                        ]
                        if interestingSubsystems.contains(logEntry.subsystem) || interestingEntries.count < 50 {
                            interestingEntries.append(entryDict)
                        }
                    }
                }
                engine.report(module: name, key: "oslogstore_entries_read", value: count)
                for (i, entry) in interestingEntries.enumerated() {
                    engine.report(module: name, key: "oslogstore_entry_\(i)", value: entry)
                }
            } catch {
                engine.reportError(module: name, key: "oslogstore_current_process", error: error.localizedDescription)
            }

            // Try system-wide scope (likely denied)
            do {
                let store = try OSLogStore.local()
                engine.report(module: name, key: "oslogstore_local", value: "accessible")

                let position = store.position(date: Date().addingTimeInterval(-30))
                let entries = try store.getEntries(at: position)
                var count = 0
                for _ in entries {
                    count += 1
                    if count > 200 { break }
                }
                engine.report(module: name, key: "oslogstore_local_entries", value: count)
            } catch {
                engine.reportError(module: name, key: "oslogstore_local", error: error.localizedDescription)
            }
        } else {
            engine.report(module: name, key: "oslogstore_available", value: false)
        }
    }

    @available(tvOS 15.0, *)
    private func logLevelString(_ level: OSLogEntryLog.Level) -> String {
        switch level {
        case .undefined: return "undefined"
        case .debug: return "debug"
        case .info: return "info"
        case .notice: return "notice"
        case .error: return "error"
        case .fault: return "fault"
        @unknown default: return "unknown(\(level.rawValue))"
        }
    }

    // MARK: - Direct Log Files

    private func probeLogFiles(engine: ReconEngine) {
        let logPaths = [
            "/var/log/system.log",
            "/var/log/syslog",
            "/private/var/log/system.log",
            "/private/var/log/syslog",
            "/var/log/asl",
            "/private/var/log/asl",
            "/var/log/DiagnosticMessages",
            "/private/var/log/DiagnosticMessages",
            "/var/log/com.apple.xpc.launchd",
            "/private/var/log/com.apple.xpc.launchd",
        ]

        for path in logPaths {
            let fm = FileManager.default
            if fm.fileExists(atPath: path) {
                var isDir: ObjCBool = false
                fm.fileExists(atPath: path, isDirectory: &isDir)

                if isDir.boolValue {
                    // Try to list directory contents
                    do {
                        let contents = try fm.contentsOfDirectory(atPath: path)
                        engine.report(module: name, key: "logfile_\(path)_type", value: "directory")
                        engine.report(module: name, key: "logfile_\(path)_contents", value: contents)
                    } catch {
                        engine.report(module: name, key: "logfile_\(path)_type", value: "directory_unreadable")
                        engine.reportError(module: name, key: "logfile_\(path)_list", error: error.localizedDescription)
                    }
                } else {
                    // Try to read first 4KB
                    if fm.isReadableFile(atPath: path) {
                        if let handle = FileHandle(forReadingAtPath: path) {
                            let data = handle.readData(ofLength: 4096)
                            handle.closeFile()
                            if let str = String(data: data, encoding: .utf8) {
                                engine.report(module: name, key: "logfile_\(path)_type", value: "file_readable")
                                engine.report(module: name, key: "logfile_\(path)_size", value: data.count)
                                engine.report(module: name, key: "logfile_\(path)_head", value: String(str.prefix(1024)))
                            } else {
                                engine.report(module: name, key: "logfile_\(path)_type", value: "file_binary")
                                engine.report(module: name, key: "logfile_\(path)_head_b64", value: data.base64EncodedString())
                            }
                        } else {
                            engine.report(module: name, key: "logfile_\(path)_type", value: "exists_but_fopen_failed")
                        }
                    } else {
                        engine.report(module: name, key: "logfile_\(path)_type", value: "exists_not_readable")
                    }
                }
            } else {
                engine.report(module: name, key: "logfile_\(path)_type", value: "not_found")
            }
        }

        // Walk /private/var/log/ for any other log files
        let logDir = "/private/var/log"
        do {
            let contents = try FileManager.default.contentsOfDirectory(atPath: logDir)
            engine.report(module: name, key: "private_var_log_contents", value: contents)
        } catch {
            engine.reportError(module: name, key: "private_var_log_list", error: error.localizedDescription)
        }
    }

    // MARK: - ASL (Apple System Logger)

    private func probeASL(engine: ReconEngine) {
        // asl_open
        let client = asl_open("TVOSRecon", "com.tvosrecon", 0)
        if client != nil {
            engine.report(module: name, key: "asl_open", value: "success")

            // Create a query for recent messages
            let query = asl_new(UInt32(ASL_TYPE_QUERY))
            if query != nil {
                // Search for all messages (no filter)
                let response = asl_search(client, query)
                if response != nil {
                    var count = 0
                    var msg = asl_next(response)
                    while msg != nil && count < 100 {
                        var entryDict: [String: String] = [:]
                        // Extract known keys
                        let keys = ["Time", "Host", "Sender", "Facility", "Level", "Message", "PID", "UID", "GID"]
                        for key in keys {
                            if let val = asl_get(msg, key) {
                                entryDict[key] = String(cString: val)
                            }
                        }
                        if !entryDict.isEmpty {
                            engine.report(module: name, key: "asl_entry_\(count)", value: entryDict)
                        }
                        count += 1
                        msg = asl_next(response)
                    }
                    engine.report(module: name, key: "asl_entries_found", value: count)
                    asl_release(response)
                } else {
                    engine.report(module: name, key: "asl_search", value: "returned nil")
                }
                asl_release(query)
            } else {
                engine.reportError(module: name, key: "asl_new_query", error: "returned nil")
            }
            asl_close(client)
        } else {
            engine.reportError(module: name, key: "asl_open", error: "returned nil")
        }
    }

    // MARK: - os_log enabled checks

    private func probeOSLogEnabled(engine: ReconEngine) {
        let subsystems = [
            "com.apple.sandbox",
            "com.apple.kernel",
            "com.apple.security",
            "com.apple.xpc",
            "com.apple.launchd",
            "com.tvosrecon.test",
        ]

        for subsystem in subsystems {
            let log = OSLog(subsystem: subsystem, category: "probe")
            engine.report(module: name, key: "os_log_enabled_\(subsystem)_default", value: log.isEnabled(type: .default))
            engine.report(module: name, key: "os_log_enabled_\(subsystem)_info", value: log.isEnabled(type: .info))
            engine.report(module: name, key: "os_log_enabled_\(subsystem)_debug", value: log.isEnabled(type: .debug))
            engine.report(module: name, key: "os_log_enabled_\(subsystem)_error", value: log.isEnabled(type: .error))
            engine.report(module: name, key: "os_log_enabled_\(subsystem)_fault", value: log.isEnabled(type: .fault))
        }

        // Test writing to os_log
        let testLog = OSLog(subsystem: "com.tvosrecon", category: "test")
        os_log("TVOSRecon test log entry", log: testLog, type: .default)
        engine.report(module: name, key: "os_log_write_test", value: "attempted")
    }
}
