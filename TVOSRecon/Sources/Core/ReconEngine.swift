import Foundation

protocol ReconEngineDelegate: AnyObject {
    func engineDidUpdateProgress(moduleName: String, moduleIndex: Int, totalModules: Int)
    func engineDidUpdateItemCount(_ count: Int)
    func engineDidFinish(summary: [String: Any])
    func engineDidStart()
}

final class ReconEngine {
    static let shared = ReconEngine()

    weak var delegate: ReconEngineDelegate?

    private let workQueue = DispatchQueue(label: "com.tvosrecon.engine", qos: .userInitiated)
    private let reportQueue = DispatchQueue(label: "com.tvosrecon.report", qos: .utility)

    private(set) var modules: [ReconModule] = []
    private(set) var currentModuleIndex: Int = 0
    private(set) var totalModules: Int = 0
    private(set) var currentModuleName: String = ""
    private(set) var totalItems: Int = 0
    private(set) var totalErrors: Int = 0
    private(set) var isRunning: Bool = false

    private var reconStartTime: Date?

    private init() {
        modules = buildModuleList()
        totalModules = modules.count
    }

    private func buildModuleList() -> [ReconModule] {
        return [
            SystemInfoModule(),
            SysctlProbeModule(),
            FileSystemWalkerModule(),
            DyldCacheInspectorModule(),
            MachInspectorModule(),
            IOKitExplorerModule(),
            SandboxProfilerModule(),
            XPCServiceProberModule(),
            NetworkProbeModule(),
            SyscallProberModule(),
            MemoryLayoutMapperModule(),
            EntitlementCheckerModule(),
            KeychainProbeModule(),
            HardwareProbeModule(),
            ProcessEnumerationModule(),
            ObjectiveCRuntimeModule(),
            MountedFilesystemsModule(),
            ResourceLimitsModule(),
            POSIXIPCProbeModule(),
            DarwinNotificationsModule(),
            NetworkServiceDiscoveryModule(),
            URLSchemeProberModule(),
            MetalGPUProbeModule(),
            MediaCapabilitiesModule(),
            CryptoCapabilitiesModule(),
            MachTrapProbeModule(),
            ClockAndTimersModule(),
            PasteboardAndAppStateModule(),
            OSLogProbeModule(),
            ThermalAndPowerProbeModule(),
            DispatchAndGCDProbeModule(),
            AccessibilityAndUIProbeModule(),
            CompilerAndRuntimeInfoModule()
        ]
    }

    func startRecon() {
        guard !isRunning else { return }
        isRunning = true
        reconStartTime = Date()
        totalItems = 0
        totalErrors = 0

        DispatchQueue.main.async {
            self.delegate?.engineDidStart()
        }

        workQueue.async { [weak self] in
            self?.runAllModules()
        }
    }

    private func runAllModules() {
        for (index, module) in modules.enumerated() {
            currentModuleIndex = index
            currentModuleName = module.name

            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                self.delegate?.engineDidUpdateProgress(
                    moduleName: module.name,
                    moduleIndex: index,
                    totalModules: self.totalModules
                )
            }

            let moduleStart = Date()
            report(module: module.name, key: "_module_start", value: ISO8601DateFormatter().string(from: moduleStart))

            let semaphore = DispatchSemaphore(value: 0)
            let timeoutInterval = module.timeout

            let moduleQueue = DispatchQueue(label: "com.tvosrecon.module.\(module.name)", qos: .userInitiated)
            moduleQueue.async {
                module.run(engine: self)
                semaphore.signal()
            }

            let result = semaphore.wait(timeout: .now() + timeoutInterval)
            let moduleEnd = Date()
            let duration = moduleEnd.timeIntervalSince(moduleStart)

            if result == .timedOut {
                reportError(module: module.name, key: "_timeout", error: "Module timed out after \(Int(timeoutInterval))s")
            }

            report(module: module.name, key: "_module_end", value: ISO8601DateFormatter().string(from: moduleEnd))
            report(module: module.name, key: "_module_duration_seconds", value: String(format: "%.2f", duration))
        }

        finishRecon()
    }

    private func finishRecon() {
        let endTime = Date()
        let totalRuntime = endTime.timeIntervalSince(reconStartTime ?? endTime)

        let summary: [String: Any] = [
            "total_items": totalItems,
            "total_errors": totalErrors,
            "modules_completed": totalModules,
            "total_runtime_seconds": String(format: "%.2f", totalRuntime),
            "start_time": ISO8601DateFormatter().string(from: reconStartTime ?? endTime),
            "end_time": ISO8601DateFormatter().string(from: endTime)
        ]

        if let jsonData = try? JSONSerialization.data(withJSONObject: [
            "module": "_summary",
            "key": "recon_complete",
            "value": summary
        ], options: []),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            NetworkServer.shared.send(jsonString)
            LocalLogger.shared.log(jsonString)
        }

        isRunning = false

        DispatchQueue.main.async { [weak self] in
            self?.delegate?.engineDidFinish(summary: summary)
        }
    }

    func report(module: String, key: String, value: String) {
        reportQueue.sync {
            self.totalItems += 1
            let escaped = escapeJSON
            let jsonLine = "{\"module\":\"\(escaped(module))\",\"key\":\"\(escaped(key))\",\"value\":\"\(escaped(value))\"}"
            NetworkServer.shared.send(jsonLine)
            LocalLogger.shared.log(jsonLine)

            if self.totalItems % 50 == 0 {
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.engineDidUpdateItemCount(self.totalItems)
                }
            }
        }
    }

    func report(module: String, key: String, value: Any) {
        if let str = value as? String {
            report(module: module, key: key, value: str)
        } else {
            reportBulk(module: module, key: key, value: value)
        }
    }

    func reportBulk(module: String, key: String, value: Any) {
        reportQueue.sync {
            self.totalItems += 1
            var dict: [String: Any] = ["module": module, "key": key]
            dict["value"] = value
            if let jsonData = try? JSONSerialization.data(withJSONObject: dict, options: []),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                NetworkServer.shared.send(jsonString)
                LocalLogger.shared.log(jsonString)
            }
        }
    }

    func reportError(module: String, key: String, error: String) {
        reportQueue.sync {
            self.totalItems += 1
            self.totalErrors += 1
            let escaped = escapeJSON
            let jsonLine = "{\"module\":\"\(escaped(module))\",\"key\":\"\(escaped(key))\",\"error\":\"\(escaped(error))\"}"
            NetworkServer.shared.send(jsonLine)
            LocalLogger.shared.log(jsonLine)
        }
    }

    private var escapeJSON: (String) -> String {
        return { str in
            str.replacingOccurrences(of: "\\", with: "\\\\")
               .replacingOccurrences(of: "\"", with: "\\\"")
               .replacingOccurrences(of: "\n", with: "\\n")
               .replacingOccurrences(of: "\r", with: "\\r")
               .replacingOccurrences(of: "\t", with: "\\t")
        }
    }
}
