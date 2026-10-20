import Foundation

final class LocalLogger {
    static let shared = LocalLogger()

    private let logQueue = DispatchQueue(label: "com.tvosrecon.logger", qos: .background)
    private var fileHandle: FileHandle?
    private(set) var logFilePath: String = ""

    private init() {
        setupLogFile()
    }

    private func setupLogFile() {
        let docs = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first
            ?? NSHomeDirectory() + "/Documents"

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = formatter.string(from: Date())
        let filename = "tvosrecon_\(timestamp).jsonl"
        logFilePath = (docs as NSString).appendingPathComponent(filename)

        let fm = FileManager.default
        if !fm.fileExists(atPath: docs) {
            try? fm.createDirectory(atPath: docs, withIntermediateDirectories: true)
        }

        fm.createFile(atPath: logFilePath, contents: nil)
        fileHandle = FileHandle(forWritingAtPath: logFilePath)
        fileHandle?.seekToEndOfFile()
    }

    func log(_ jsonLine: String) {
        logQueue.async { [weak self] in
            guard let data = (jsonLine + "\n").data(using: .utf8) else { return }
            self?.fileHandle?.write(data)
        }
    }

    deinit {
        fileHandle?.closeFile()
    }
}
