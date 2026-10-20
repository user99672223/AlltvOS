// NetworkProbeModule.swift
// Enumerates network interfaces, tests socket creation for all address families,
// probes port binding, socket options, DNS resolver config, routing tables, and
// network path status. Maps the full network capability surface of the sandbox.

import Foundation
#if canImport(Network)
import Network
#endif

final class NetworkProbeModule: ReconModule {
    let name = "NetworkProbe"
    let timeout: TimeInterval = 60

    func run(engine: ReconEngine) {
        enumerateInterfaces(engine: engine)
        enumerateInterfaceIndices(engine: engine)
        testSocketCreation(engine: engine)
        testRawSocketProtocols(engine: engine)
        testPortBinding(engine: engine)
        testSocketOptions(engine: engine)
        probeDNSResolver(engine: engine)
        probeRoutingTable(engine: engine)
        probeNetworkPath(engine: engine)
    }

    // MARK: - Interface Enumeration

    private func enumerateInterfaces(engine: ReconEngine) {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            engine.reportError(module: name, key: "getifaddrs", error: "failed: errno \(errno) - \(String(cString: strerror(errno)))")
            return
        }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        var count = 0
        while let addr = ptr {
            count += 1
            let ifName = String(cString: addr.pointee.ifa_name)
            let flags = addr.pointee.ifa_flags

            var entry: [String: Any] = [
                "name": ifName,
                "flags_raw": flags,
                "flags": decodeIfFlags(flags)
            ]

            if let sa = addr.pointee.ifa_addr {
                entry["family"] = addressFamilyName(Int32(sa.pointee.sa_family))
                entry["address"] = sockaddrToString(sa)

                if let netmask = addr.pointee.ifa_netmask {
                    entry["netmask"] = sockaddrToString(netmask)
                }

                if (flags & UInt32(IFF_BROADCAST)) != 0, let brd = addr.pointee.ifa_dstaddr {
                    entry["broadcast"] = sockaddrToString(brd)
                } else if (flags & UInt32(IFF_POINTOPOINT)) != 0, let dst = addr.pointee.ifa_dstaddr {
                    entry["destination"] = sockaddrToString(dst)
                }
            }

            // Get MTU via ioctl
            let sock = socket(AF_INET, SOCK_DGRAM, 0)
            if sock >= 0 {
                var ifr = ifreq()
                withUnsafeMutablePointer(to: &ifr.ifr_name) { namePtr in
                    namePtr.withMemoryRebound(to: CChar.self, capacity: Int(IFNAMSIZ)) { ptr in
                        _ = strncpy(ptr, ifName, Int(IFNAMSIZ) - 1)
                    }
                }
                if ioctl(sock, 0xC0206933, &ifr) == 0 {
                    entry["mtu"] = ifr.ifr_ifru.ifru_mtu
                }
                close(sock)
            }

            engine.report(module: name, key: "interface", value: entry)
            ptr = addr.pointee.ifa_next
        }
        engine.report(module: name, key: "interface_count", value: count)
    }

    private func enumerateInterfaceIndices(engine: ReconEngine) {
        guard let nameindex = if_nameindex() else {
            engine.reportError(module: name, key: "if_nameindex", error: "failed: errno \(errno)")
            return
        }
        defer { if_freenameindex(nameindex) }

        var idx = nameindex
        var entries: [[String: Any]] = []
        while idx.pointee.if_index != 0 {
            let ifName = String(cString: idx.pointee.if_name)
            entries.append(["index": idx.pointee.if_index, "name": ifName])
            idx = idx.advanced(by: 1)
        }
        engine.report(module: name, key: "interface_indices", value: entries)
    }

    // MARK: - Socket Creation Tests

    private func testSocketCreation(engine: ReconEngine) {
        let socketTypes: [(String, Int32, Int32, Int32)] = [
            ("AF_INET/SOCK_STREAM", AF_INET, SOCK_STREAM, 0),
            ("AF_INET/SOCK_DGRAM", AF_INET, SOCK_DGRAM, 0),
            ("AF_INET/SOCK_RAW", AF_INET, SOCK_RAW, 0),
            ("AF_INET6/SOCK_STREAM", AF_INET6, SOCK_STREAM, 0),
            ("AF_INET6/SOCK_DGRAM", AF_INET6, SOCK_DGRAM, 0),
            ("AF_INET6/SOCK_RAW", AF_INET6, SOCK_RAW, 0),
            ("AF_UNIX/SOCK_STREAM", AF_UNIX, SOCK_STREAM, 0),
            ("AF_UNIX/SOCK_DGRAM", AF_UNIX, SOCK_DGRAM, 0),
            ("AF_SYSTEM/SOCK_DGRAM", AF_SYSTEM, SOCK_DGRAM, 0),
            ("AF_NDRV/SOCK_RAW", AF_NDRV, SOCK_RAW, 0),
            ("AF_ROUTE/SOCK_RAW", AF_ROUTE, SOCK_RAW, 0),
            ("AF_LINK/SOCK_RAW", AF_LINK, SOCK_RAW, 0)
        ]

        for (desc, domain, type, proto) in socketTypes {
            let fd = socket(domain, type, proto)
            var result: [String: Any] = [
                "description": desc,
                "domain": domain,
                "type": type,
                "protocol": proto
            ]
            if fd >= 0 {
                result["success"] = true
                result["fd"] = fd
                close(fd)
            } else {
                result["success"] = false
                result["errno"] = Int(errno)
                result["error"] = String(cString: strerror(errno))
            }
            engine.report(module: name, key: "socket_create", value: result)
        }
    }

    private func testRawSocketProtocols(engine: ReconEngine) {
        let protocols: [(String, Int32)] = [
            ("IPPROTO_ICMP", IPPROTO_ICMP),
            ("IPPROTO_TCP", IPPROTO_TCP),
            ("IPPROTO_UDP", IPPROTO_UDP),
            ("IPPROTO_RAW", IPPROTO_RAW),
            ("IPPROTO_DIVERT", 254) // IPPROTO_DIVERT
        ]

        for (protoName, proto) in protocols {
            let fd = socket(AF_INET, SOCK_RAW, proto)
            var result: [String: Any] = ["protocol": protoName, "protocol_num": proto]
            if fd >= 0 {
                result["success"] = true
                close(fd)
            } else {
                result["success"] = false
                result["errno"] = Int(errno)
                result["error"] = String(cString: strerror(errno))
            }
            engine.report(module: name, key: "raw_socket_protocol", value: result)
        }
    }

    // MARK: - Port Binding Tests

    private func testPortBinding(engine: ReconEngine) {
        let testPorts: [UInt16] = [22, 53, 80, 443, 548, 8080, 9100, 49152]

        for port in testPorts {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else {
                engine.reportError(module: name, key: "port_bind_\(port)", error: "socket creation failed")
                continue
            }

            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = INADDR_ANY

            let bindResult = withUnsafePointer(to: &addr) { addrPtr -> Int32 in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bind(fd, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            var result: [String: Any] = ["port": port]
            if bindResult == 0 {
                result["success"] = true
            } else {
                result["success"] = false
                result["errno"] = Int(errno)
                result["error"] = String(cString: strerror(errno))
            }
            engine.report(module: name, key: "port_bind", value: result)
            close(fd)
        }
    }

    // MARK: - Socket Options

    private func testSocketOptions(engine: ReconEngine) {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else {
            engine.reportError(module: name, key: "socket_options", error: "socket creation failed")
            return
        }
        defer { close(fd) }

        let options: [(String, Int32, Int32)] = [
            ("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR),
            ("SO_BROADCAST", SOL_SOCKET, SO_BROADCAST),
            ("SO_SNDBUF", SOL_SOCKET, SO_SNDBUF),
            ("SO_RCVBUF", SOL_SOCKET, SO_RCVBUF)
        ]

        for (optName, level, opt) in options {
            var val: Int32 = 1
            let result = setsockopt(fd, level, opt, &val, socklen_t(MemoryLayout<Int32>.size))
            engine.report(module: name, key: "setsockopt", value: [
                "option": optName,
                "success": result == 0,
                "errno": result != 0 ? Int(errno) : 0,
                "error": result != 0 ? String(cString: strerror(errno)) : ""
            ] as [String: Any])
        }

        // IP_HDRINCL on raw socket
        let rawFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
        if rawFd >= 0 {
            var val: Int32 = 1
            let r = setsockopt(rawFd, IPPROTO_IP, IP_HDRINCL, &val, socklen_t(MemoryLayout<Int32>.size))
            engine.report(module: name, key: "setsockopt", value: [
                "option": "IP_HDRINCL",
                "success": r == 0,
                "errno": r != 0 ? Int(errno) : 0
            ] as [String: Any])
            close(rawFd)
        } else {
            engine.report(module: name, key: "setsockopt", value: [
                "option": "IP_HDRINCL",
                "success": false,
                "error": "raw socket creation failed"
            ] as [String: Any])
        }

        // IP_MULTICAST_IF
        let udpFd = socket(AF_INET, SOCK_DGRAM, 0)
        if udpFd >= 0 {
            var mreq = in_addr(s_addr: INADDR_ANY)
            let r = setsockopt(udpFd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, socklen_t(MemoryLayout<in_addr>.size))
            engine.report(module: name, key: "setsockopt", value: [
                "option": "IP_MULTICAST_IF",
                "success": r == 0,
                "errno": r != 0 ? Int(errno) : 0
            ] as [String: Any])
            close(udpFd)
        }

        // IPV6_V6ONLY
        let fd6 = socket(AF_INET6, SOCK_STREAM, 0)
        if fd6 >= 0 {
            var val: Int32 = 1
            let r = setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &val, socklen_t(MemoryLayout<Int32>.size))
            engine.report(module: name, key: "setsockopt", value: [
                "option": "IPV6_V6ONLY",
                "success": r == 0,
                "errno": r != 0 ? Int(errno) : 0
            ] as [String: Any])
            close(fd6)
        }
    }

    // MARK: - DNS Resolver

    private func probeDNSResolver(engine: ReconEngine) {
        var state = __res_9_state()
        let initResult = res_9_ninit(&state)
        engine.report(module: name, key: "dns_resolver_init", value: [
            "result": initResult,
            "success": initResult == 0
        ] as [String: Any])

        if initResult == 0 {
            // Number of nameservers
            let nsCount = Int(state.nscount)
            engine.report(module: name, key: "dns_nameserver_count", value: nsCount)

            // Extract nameserver addresses
            for i in 0..<min(nsCount, 3) {
                var nsAddr = state.nsaddr_list.0
                // Access nsaddr_list elements via offset
                withUnsafePointer(to: &state.nsaddr_list) { ptr in
                    let base = UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr_in.self)
                    nsAddr = base[i]
                }
                var addrStr = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                var sinAddr = nsAddr.sin_addr
                inet_ntop(AF_INET, &sinAddr, &addrStr, socklen_t(INET_ADDRSTRLEN))
                engine.report(module: name, key: "dns_nameserver", value: [
                    "index": i,
                    "address": String(cString: addrStr),
                    "port": UInt16(bigEndian: nsAddr.sin_port)
                ] as [String: Any])
            }

            // Search domains
            let defdname = withUnsafePointer(to: state.defdname) { ptr -> String in
                let raw = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                return String(cString: raw)
            }
            engine.report(module: name, key: "dns_default_domain", value: defdname)

            // Options
            engine.report(module: name, key: "dns_options", value: [
                "retrans": state.retrans,
                "retry": state.retry,
                "options": state.options,
                "ndots": state.ndots
            ] as [String: Any])

            res_9_ndestroy(&state)
        }
    }

    // MARK: - Routing Table

    private func probeRoutingTable(engine: ReconEngine) {
        // Try NET_RT_DUMP
        let rtTypes: [(String, Int32)] = [
            ("NET_RT_DUMP", NET_RT_DUMP),
            ("NET_RT_FLAGS", NET_RT_FLAGS),
            ("NET_RT_IFLIST", NET_RT_IFLIST)
        ]

        for (typeName, rtType) in rtTypes {
            var mib: [Int32] = [CTL_NET, AF_ROUTE, 0, 0, rtType, 0]
            var size: Int = 0
            let ret = sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0)

            var result: [String: Any] = ["type": typeName]
            if ret == 0 {
                result["success"] = true
                result["buffer_size"] = size

                if size > 0 && size < 1024 * 1024 { // Cap at 1MB
                    var buf = [UInt8](repeating: 0, count: size)
                    let ret2 = sysctl(&mib, UInt32(mib.count), &buf, &size, nil, 0)
                    result["read_success"] = ret2 == 0
                    result["actual_size"] = size
                    if rtType == NET_RT_IFLIST {
                        // Count interface entries
                        result["data_available"] = true
                    }
                }
            } else {
                result["success"] = false
                result["errno"] = Int(errno)
                result["error"] = String(cString: strerror(errno))
            }
            engine.report(module: name, key: "routing_table", value: result)
        }
    }

    // MARK: - NWPathMonitor

    private func probeNetworkPath(engine: ReconEngine) {
        #if canImport(Network)
        let monitor = NWPathMonitor()
        let semaphore = DispatchSemaphore(value: 0)
        var pathInfo: [String: Any]?

        monitor.pathUpdateHandler = { path in
            var info: [String: Any] = [
                "status": "\(path.status)",
                "isExpensive": path.isExpensive,
                "isConstrained": path.isConstrained,
                "supportsIPv4": path.supportsIPv4,
                "supportsIPv6": path.supportsIPv6,
                "supportsDNS": path.supportsDNS
            ]

            var interfaces: [[String: Any]] = []
            for iface in path.availableInterfaces {
                interfaces.append([
                    "name": iface.name,
                    "type": "\(iface.type)",
                    "index": iface.index
                ])
            }
            info["availableInterfaces"] = interfaces
            pathInfo = info
            semaphore.signal()
        }

        let queue = DispatchQueue(label: "com.tvosrecon.networkpath")
        monitor.start(queue: queue)

        let _ = semaphore.wait(timeout: .now() + 5.0)
        monitor.cancel()

        if let info = pathInfo {
            engine.report(module: name, key: "network_path", value: info)
        } else {
            engine.reportError(module: name, key: "network_path", error: "timeout waiting for path update")
        }
        #else
        engine.reportError(module: name, key: "network_path", error: "Network framework not available")
        #endif
    }

    // MARK: - Helpers

    private func sockaddrToString(_ sa: UnsafePointer<sockaddr>) -> String {
        let family = sa.pointee.sa_family
        switch Int32(family) {
        case AF_INET:
            var addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buf)
        case AF_INET6:
            var addr = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buf)
        case AF_LINK:
            return "<link-layer>"
        default:
            return "<family:\(family)>"
        }
    }

    private func addressFamilyName(_ family: Int32) -> String {
        switch family {
        case AF_INET: return "AF_INET"
        case AF_INET6: return "AF_INET6"
        case AF_UNIX: return "AF_UNIX"
        case AF_LINK: return "AF_LINK"
        case AF_ROUTE: return "AF_ROUTE"
        case AF_SYSTEM: return "AF_SYSTEM"
        default: return "AF_\(family)"
        }
    }

    private func decodeIfFlags(_ flags: UInt32) -> [String] {
        var result: [String] = []
        let flagMap: [(UInt32, String)] = [
            (UInt32(IFF_UP), "UP"),
            (UInt32(IFF_BROADCAST), "BROADCAST"),
            (UInt32(IFF_DEBUG), "DEBUG"),
            (UInt32(IFF_LOOPBACK), "LOOPBACK"),
            (UInt32(IFF_POINTOPOINT), "POINTOPOINT"),
            (UInt32(IFF_RUNNING), "RUNNING"),
            (UInt32(IFF_NOARP), "NOARP"),
            (UInt32(IFF_PROMISC), "PROMISC"),
            (UInt32(IFF_ALLMULTI), "ALLMULTI"),
            (UInt32(IFF_MULTICAST), "MULTICAST")
        ]
        for (flag, label) in flagMap {
            if (flags & flag) != 0 {
                result.append(label)
            }
        }
        return result
    }
}
