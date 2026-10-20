// MountedFilesystemsModule.swift
// TVOSRecon
//
// Enumerates all mounted filesystems and their properties. This reveals
// the full storage layout of tvOS: which partitions exist, their mount
// flags (read-only, nosuid, noexec), filesystem types, and capacity.
// Security researchers should look for: writable partitions that could
// be exploited, APFS snapshot mounts that reveal the system volume
// structure, missing noexec flags that allow code execution from
// unexpected locations, and total storage layout.

import Foundation
import Darwin

final class MountedFilesystemsModule: ReconModule {
    let name = "MountedFilesystems"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        enumerateMounts(engine: engine)
        probePathconf(engine: engine)
        probeStatfs(engine: engine)
        testMountOperations(engine: engine)
    }

    // MARK: - Enumerate Mounts

    private func enumerateMounts(engine: ReconEngine) {
        var mntbuf: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&mntbuf, MNT_NOWAIT)

        guard count > 0, let mounts = mntbuf else {
            engine.reportError(module: name, key: "mounts", error: "getmntinfo returned \(count), errno=\(errno)")
            return
        }

        engine.report(module: name, key: "mounts.count", value: count)

        for i in 0..<Int(count) {
            let fs = mounts[i]
            let prefix = "mount[\(i)]"

            let mountPoint = withUnsafePointer(to: fs.f_mntonname) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }
            let fsTypeName = withUnsafePointer(to: fs.f_fstypename) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) {
                    String(cString: $0)
                }
            }
            let deviceName = withUnsafePointer(to: fs.f_mntfromname) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }

            engine.report(module: name, key: "\(prefix).mountPoint", value: mountPoint)
            engine.report(module: name, key: "\(prefix).fsType", value: fsTypeName)
            engine.report(module: name, key: "\(prefix).device", value: deviceName)
            engine.report(module: name, key: "\(prefix).flags", value: String(format: "0x%x", fs.f_flags))
            engine.report(module: name, key: "\(prefix).flagsDecoded", value: decodeMountFlags(fs.f_flags))

            engine.report(module: name, key: "\(prefix).blockSize", value: fs.f_bsize)
            engine.report(module: name, key: "\(prefix).ioSize", value: fs.f_iosize)
            engine.report(module: name, key: "\(prefix).totalBlocks", value: fs.f_blocks)
            engine.report(module: name, key: "\(prefix).freeBlocks", value: fs.f_bfree)
            engine.report(module: name, key: "\(prefix).availableBlocks", value: fs.f_bavail)
            engine.report(module: name, key: "\(prefix).totalFiles", value: fs.f_files)
            engine.report(module: name, key: "\(prefix).freeFiles", value: fs.f_ffree)
            engine.report(module: name, key: "\(prefix).fsSubtype", value: fs.f_fssubtype)
            engine.report(module: name, key: "\(prefix).owner", value: fs.f_owner)
            engine.report(module: name, key: "\(prefix).fsid", value: "\(fs.f_fsid.val.0).\(fs.f_fsid.val.1)")

            let totalBytes = UInt64(fs.f_blocks) * UInt64(fs.f_bsize)
            let freeBytes = UInt64(fs.f_bfree) * UInt64(fs.f_bsize)
            let availBytes = UInt64(fs.f_bavail) * UInt64(fs.f_bsize)
            let usedBytes = totalBytes > freeBytes ? totalBytes - freeBytes : 0

            engine.report(module: name, key: "\(prefix).totalBytes", value: totalBytes)
            engine.report(module: name, key: "\(prefix).freeBytes", value: freeBytes)
            engine.report(module: name, key: "\(prefix).availableBytes", value: availBytes)
            engine.report(module: name, key: "\(prefix).usedBytes", value: usedBytes)

            if totalBytes > 0 {
                let usedPct = Double(usedBytes) / Double(totalBytes) * 100.0
                engine.report(module: name, key: "\(prefix).usedPercent",
                              value: String(format: "%.1f%%", usedPct))
            }
        }
    }

    private func decodeMountFlags(_ flags: UInt32) -> String {
        var decoded: [String] = []
        let flagMap: [(UInt32, String)] = [
            (UInt32(MNT_RDONLY), "MNT_RDONLY"),
            (UInt32(MNT_SYNCHRONOUS), "MNT_SYNCHRONOUS"),
            (UInt32(MNT_NOEXEC), "MNT_NOEXEC"),
            (UInt32(MNT_NOSUID), "MNT_NOSUID"),
            (UInt32(MNT_NODEV), "MNT_NODEV"),
            (UInt32(MNT_UNION), "MNT_UNION"),
            (UInt32(MNT_ASYNC), "MNT_ASYNC"),
            (UInt32(MNT_EXPORTED), "MNT_EXPORTED"),
            (UInt32(MNT_LOCAL), "MNT_LOCAL"),
            (UInt32(MNT_QUOTA), "MNT_QUOTA"),
            (UInt32(MNT_ROOTFS), "MNT_ROOTFS"),
            (UInt32(MNT_DOVOLFS), "MNT_DOVOLFS"),
            (UInt32(MNT_DONTBROWSE), "MNT_DONTBROWSE"),
            (UInt32(MNT_IGNORE_OWNERSHIP), "MNT_IGNORE_OWNERSHIP"),
            (UInt32(MNT_AUTOMOUNTED), "MNT_AUTOMOUNTED"),
            (UInt32(MNT_JOURNALED), "MNT_JOURNALED"),
            (UInt32(MNT_NOUSERXATTR), "MNT_NOUSERXATTR"),
            (UInt32(MNT_DEFWRITE), "MNT_DEFWRITE"),
            (UInt32(MNT_MULTILABEL), "MNT_MULTILABEL"),
            (UInt32(MNT_NOATIME), "MNT_NOATIME"),
            (UInt32(MNT_SNAPSHOT), "MNT_SNAPSHOT"),
        ]
        for (flag, label) in flagMap {
            if flags & flag != 0 {
                decoded.append(label)
            }
        }
        if UInt32(MNT_REMOVABLE) != 0 && flags & UInt32(MNT_REMOVABLE) != 0 {
            decoded.append("MNT_REMOVABLE")
        }
        return decoded.isEmpty ? "none" : decoded.joined(separator: " | ")
    }

    // MARK: - pathconf

    private func probePathconf(engine: ReconEngine) {
        let paths = ["/", "/tmp", "/var", "/System", NSHomeDirectory()]
        let confNames: [(String, Int32)] = [
            ("NAME_MAX", _PC_NAME_MAX),
            ("PATH_MAX", _PC_PATH_MAX),
            ("LINK_MAX", _PC_LINK_MAX),
            ("SYMLINK_MAX", _PC_SYMLINK_MAX),
            ("CASE_SENSITIVE", _PC_CASE_SENSITIVE),
            ("CASE_PRESERVING", _PC_CASE_PRESERVING),
            ("FILESIZEBITS", _PC_FILESIZEBITS),
            ("NO_TRUNC", _PC_NO_TRUNC),
            ("XATTR_SIZE_BITS", _PC_XATTR_SIZE_BITS),
        ]

        for path in paths {
            for (confName, confValue) in confNames {
                errno = 0
                let result = pathconf(path, confValue)
                if result == -1 && errno != 0 {
                    engine.reportError(module: name, key: "pathconf.\(path).\(confName)",
                                       error: "errno=\(errno)")
                } else {
                    engine.report(module: name, key: "pathconf.\(path).\(confName)", value: result)
                }
            }
        }

        let fpathConfNames: [(String, Int32)] = [
            ("NAME_MAX", _PC_NAME_MAX),
            ("PATH_MAX", _PC_PATH_MAX),
            ("LINK_MAX", _PC_LINK_MAX),
            ("FILESIZEBITS", _PC_FILESIZEBITS),
            ("MIN_HOLE_SIZE", _PC_MIN_HOLE_SIZE),
        ]

        let tmpFd = open(NSTemporaryDirectory(), O_RDONLY)
        if tmpFd >= 0 {
            for (confName, confValue) in fpathConfNames {
                errno = 0
                let result = fpathconf(tmpFd, confValue)
                if result == -1 && errno != 0 {
                    engine.reportError(module: name, key: "fpathconf.tmpdir.\(confName)",
                                       error: "errno=\(errno)")
                } else {
                    engine.report(module: name, key: "fpathconf.tmpdir.\(confName)", value: result)
                }
            }
            close(tmpFd)
        }
    }

    // MARK: - statfs on various paths

    private func probeStatfs(engine: ReconEngine) {
        let paths = ["/", "/tmp", "/var", "/System", "/private",
                     "/usr", "/dev", "/Library", NSHomeDirectory(),
                     "/private/var", "/private/var/mobile",
                     "/System/Library", "/Applications"]

        for path in paths {
            // Unqualified: Darwin.statfs resolves to the struct type, not the function.
            var buf = statfs()
            let result = statfs(path, &buf)
            if result == 0 {
                let fsType = withUnsafePointer(to: buf.f_fstypename) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSNAMELEN)) {
                        String(cString: $0)
                    }
                }
                let mountOn = withUnsafePointer(to: buf.f_mntonname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                        String(cString: $0)
                    }
                }
                let device = withUnsafePointer(to: buf.f_mntfromname) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                        String(cString: $0)
                    }
                }
                engine.report(module: name, key: "statfs.\(path).fsType", value: fsType)
                engine.report(module: name, key: "statfs.\(path).mountPoint", value: mountOn)
                engine.report(module: name, key: "statfs.\(path).device", value: device)
                engine.report(module: name, key: "statfs.\(path).flags", value: decodeMountFlags(buf.f_flags))
                let totalBytes = UInt64(buf.f_blocks) * UInt64(buf.f_bsize)
                let availBytes = UInt64(buf.f_bavail) * UInt64(buf.f_bsize)
                engine.report(module: name, key: "statfs.\(path).totalBytes", value: totalBytes)
                engine.report(module: name, key: "statfs.\(path).availableBytes", value: availBytes)
            } else {
                engine.reportError(module: name, key: "statfs.\(path)", error: "failed errno=\(errno)")
            }
        }
    }

    // MARK: - Mount/Unmount Tests

    private func testMountOperations(engine: ReconEngine) {
        let tmpPath = NSTemporaryDirectory() + "mount_test"
        mkdir(tmpPath, 0o755)
        defer { rmdir(tmpPath) }

        let mountResult = mount("tmpfs", tmpPath, MNT_RDONLY, nil)
        engine.report(module: name, key: "mountTest.mount.result", value: mountResult)
        engine.report(module: name, key: "mountTest.mount.errno", value: errno)
        engine.report(module: name, key: "mountTest.mount.errnoName", value: errnoName(errno))

        let unmountResult = unmount("/tmp", 0)
        engine.report(module: name, key: "mountTest.unmount_tmp.result", value: unmountResult)
        engine.report(module: name, key: "mountTest.unmount_tmp.errno", value: errno)
        engine.report(module: name, key: "mountTest.unmount_tmp.errnoName", value: errnoName(errno))

        let unmountRoot = unmount("/", 0)
        engine.report(module: name, key: "mountTest.unmount_root.result", value: unmountRoot)
        engine.report(module: name, key: "mountTest.unmount_root.errno", value: errno)
    }

    private func errnoName(_ err: Int32) -> String {
        switch err {
        case 0: return "success"
        case EPERM: return "EPERM"
        case ENOENT: return "ENOENT"
        case EACCES: return "EACCES"
        case EBUSY: return "EBUSY"
        case EINVAL: return "EINVAL"
        case ENOSYS: return "ENOSYS"
        case ENOTSUP: return "ENOTSUP"
        case EROFS: return "EROFS"
        default: return "errno(\(err))"
        }
    }
}
