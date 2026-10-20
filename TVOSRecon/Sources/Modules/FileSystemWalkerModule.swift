// FileSystemWalkerModule.swift
// Recursively enumerates the filesystem to map what a sandboxed app can see.
// Each entry records path, type, size, permissions, ownership, xattrs,
// dates, and flags. Interesting small files are sampled and plists are
// deserialized. Paths that exist but are unreadable are logged as denied.
// This reveals the sandbox boundary from the inside.

import Foundation

final class FileSystemWalkerModule: ReconModule {
    let name = "FileSystemWalker"
    let timeout: TimeInterval = 120

    func run(engine: ReconEngine) {
        let paths: [(String, Int)] = [
            (NSHomeDirectory(), Int.max),
            ("/System", 4),
            ("/System/Library/LaunchDaemons", Int.max),
            ("/System/Library/XPCServices", Int.max),
            ("/System/Library/PrivateFrameworks", 2),
            ("/System/Library/Frameworks", 2),
            ("/System/Library/Caches/com.apple.dyld", Int.max),
            ("/usr", 4),
            ("/usr/lib", 3),
            ("/private", 3),
            ("/private/var/run", Int.max),
            ("/private/var/mobile", 2),
            ("/private/var/db", 2),
            ("/private/var/log", 2),
            ("/var", 3),
            ("/dev", Int.max),
            ("/etc", Int.max),
            ("/tmp", Int.max),
            ("/bin", Int.max),
            ("/sbin", Int.max),
            ("/usr/bin", Int.max),
            ("/usr/sbin", Int.max),
            ("/Library", 3),
            ("/Applications", 2),
            ("/cores", Int.max),
            ("/opt", Int.max),
            ("/AppleInternal", Int.max),
        ]

        for (path, maxDepth) in paths {
            walkPath(path, currentDepth: 0, maxDepth: maxDepth, engine: engine)
        }
    }

    private func walkPath(_ path: String, currentDepth: Int, maxDepth: Int, engine: ReconEngine) {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let exists = fm.fileExists(atPath: path, isDirectory: &isDir)

        if !exists {
            return
        }

        reportEntry(path: path, engine: engine)

        guard isDir.boolValue, currentDepth < maxDepth else { return }

        do {
            let contents = try fm.contentsOfDirectory(atPath: path)
            for item in contents.sorted() {
                let fullPath = (path as NSString).appendingPathComponent(item)
                walkPath(fullPath, currentDepth: currentDepth + 1, maxDepth: maxDepth, engine: engine)
            }
        } catch {
            engine.reportError(module: name, key: "walk.\(path)", error: "exists_but_denied: \(error.localizedDescription)")
        }
    }

    private func reportEntry(path: String, engine: ReconEngine) {
        let fm = FileManager.default
        var info: [String: Any] = ["path": path]

        do {
            let attrs = try fm.attributesOfItem(atPath: path)

            // Type
            if let fileType = attrs[.type] as? FileAttributeType {
                let typeStr: String
                switch fileType {
                case .typeRegular: typeStr = "file"
                case .typeDirectory: typeStr = "dir"
                case .typeSymbolicLink: typeStr = "symlink"
                case .typeCharacterSpecial: typeStr = "device_char"
                case .typeBlockSpecial: typeStr = "device_block"
                case .typeSocket: typeStr = "socket"
                case .typeUnknown: typeStr = "unknown"
                default: typeStr = "other"
                }
                info["type"] = typeStr
            }

            // Size
            if let size = attrs[.size] as? UInt64 {
                info["size"] = size
            }

            // Permissions
            if let posix = attrs[.posixPermissions] as? Int {
                info["permissions"] = String(format: "%04o", posix)
            }

            // Owner
            if let uid = attrs[.ownerAccountID] as? NSNumber {
                info["uid"] = uid.intValue
            }
            if let gid = attrs[.groupOwnerAccountID] as? NSNumber {
                info["gid"] = gid.intValue
            }

            // Dates
            if let created = attrs[.creationDate] as? Date {
                info["created"] = ISO8601DateFormatter().string(from: created)
            }
            if let modified = attrs[.modificationDate] as? Date {
                info["modified"] = ISO8601DateFormatter().string(from: modified)
            }

            // Readable / writable / executable
            info["readable"] = fm.isReadableFile(atPath: path)
            info["writable"] = fm.isWritableFile(atPath: path)
            info["executable"] = fm.isExecutableFile(atPath: path)

            // Symlink target
            if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
                do {
                    let target = try fm.destinationOfSymbolicLink(atPath: path)
                    info["symlinkTarget"] = target
                } catch {
                    info["symlinkTarget"] = "error: \(error.localizedDescription)"
                }
            }

            // File flags (stat-based)
            var st = stat()
            if lstat(path, &st) == 0 {
                info["flags"] = st.st_flags
            }

            // Extended attributes
            let xattrList = listXattrs(path: path)
            if !xattrList.isEmpty {
                var xattrs: [String: String] = [:]
                for attr in xattrList {
                    if let val = getXattr(path: path, name: attr) {
                        if val.count <= 256 {
                            xattrs[attr] = val.base64EncodedString()
                        } else {
                            xattrs[attr] = "[\(val.count) bytes]"
                        }
                    } else {
                        xattrs[attr] = "read_error"
                    }
                }
                info["xattrs"] = xattrs
            }

            engine.report(module: name, key: "entry", value: info)

            // Try to read interesting file contents
            let fileType = attrs[.type] as? FileAttributeType
            let size = (attrs[.size] as? UInt64) ?? 0
            if fileType == .typeRegular && fm.isReadableFile(atPath: path) {
                let ext = (path as NSString).pathExtension.lowercased()
                let isInteresting = ["plist", "conf", "cfg", "ini", "json", "xml", "db", "sqlite", "strings", "entitlements"].contains(ext)
                    || path.hasSuffix(".mobileprovision")
                let shouldSample = isInteresting || size < 4096

                if shouldSample && size > 0 && size < 1_000_000 {
                    sampleFile(path: path, ext: ext, engine: engine)
                }
            }
        } catch {
            engine.reportError(module: name, key: "entry", error: "path=\(path) exists_but_denied: \(error.localizedDescription)")
        }
    }

    private func sampleFile(path: String, ext: String, engine: ReconEngine) {
        guard let fh = FileHandle(forReadingAtPath: path) else { return }
        defer { fh.closeFile() }

        let data = fh.readData(ofLength: 256)
        guard !data.isEmpty else { return }

        // Try plist deserialization
        if ext == "plist" || ext == "entitlements" {
            do {
                let fullData: Data
                if let d = FileManager.default.contents(atPath: path), d.count < 65536 {
                    fullData = d
                } else {
                    fullData = data
                }
                let plist = try PropertyListSerialization.propertyList(from: fullData, options: [], format: nil)
                if let jsonData = try? JSONSerialization.data(withJSONObject: plist, options: [.sortedKeys]),
                   let jsonString = String(data: jsonData, encoding: .utf8) {
                    engine.report(module: name, key: "file_content_plist", value: ["path": path, "json": jsonString])
                    return
                }
            } catch {
                // Fall through to base64
            }
        }

        engine.report(module: name, key: "file_content_sample", value: ["path": path, "base64": data.base64EncodedString(), "bytes": data.count])
    }

    private func listXattrs(path: String) -> [String] {
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return [] }
        var buf = [CChar](repeating: 0, count: size)
        let actual = listxattr(path, &buf, size, XATTR_NOFOLLOW)
        guard actual > 0 else { return [] }
        let raw = Data(bytes: buf, count: actual)
        return raw.split(separator: 0).compactMap { String(bytes: $0, encoding: .utf8) }
    }

    private func getXattr(path: String, name: String) -> Data? {
        let size = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        let actual = getxattr(path, name, &buf, size, 0, XATTR_NOFOLLOW)
        guard actual > 0 else { return nil }
        return Data(buf.prefix(actual))
    }
}
