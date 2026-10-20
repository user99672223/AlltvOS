// NetworkServiceDiscoveryModule.swift
// TVOSRecon - Module 21: Network Service Discovery
//
// Uses Bonjour (mDNS/DNS-SD) to discover all advertised services on the
// local network. This reveals other Apple devices, AirPlay targets, HomeKit
// accessories, smart home gear, printers, and any other discoverable devices.
// Important for understanding the network context and potential lateral
// movement targets.

import Foundation

final class NetworkServiceDiscoveryModule: ReconModule {
    let name = "NetworkServiceDiscovery"
    let timeout: TimeInterval = 30

    func run(engine: ReconEngine) {
        let delegate = DiscoveryDelegate(engine: engine, moduleName: name)
        delegate.discover()
    }
}

private final class DiscoveryDelegate: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    private let engine: ReconEngine
    private let moduleName: String

    private var metaBrowser: NetServiceBrowser?
    private var typeBrowsers: [String: NetServiceBrowser] = [:]
    private var resolvingServices: [NetService] = []
    private var discoveredTypes: Set<String> = Set()
    private var allResults: [[String: Any]] = []
    private let lock = NSLock()

    init(engine: ReconEngine, moduleName: String) {
        self.engine = engine
        self.moduleName = moduleName
        super.init()
    }

    func discover() {
        // Phase 1: meta-query to discover all service types
        metaBrowser = NetServiceBrowser()
        metaBrowser?.delegate = self
        metaBrowser?.searchForServices(ofType: "_services._dns-sd._udp.", inDomain: "local.")

        // Phase 2: also browse for specific known service types directly
        let specificTypes = [
            "_airplay._tcp.",
            "_raop._tcp.",
            "_homekit._tcp.",
            "_companion-link._tcp.",
            "_sleep-proxy._udp.",
            "_http._tcp.",
            "_https._tcp.",
            "_ssh._tcp.",
            "_smb._tcp.",
            "_afpovertcp._tcp.",
            "_nfs._tcp.",
            "_ipp._tcp.",
            "_printer._tcp.",
            "_scanner._tcp.",
            "_daap._tcp.",
            "_appletv-v2._tcp.",
            "_touch-able._tcp.",
            "_airport._tcp.",
            "_device-info._tcp.",
            "_apple-mobdev2._tcp.",
            "_mediaremotetv._tcp.",
            "_hap._tcp.",
            "_matter._tcp.",
            "_coap._udp."
        ]

        for serviceType in specificTypes {
            lock.lock()
            if !discoveredTypes.contains(serviceType) {
                discoveredTypes.insert(serviceType)
                lock.unlock()
                browseType(serviceType)
            } else {
                lock.unlock()
            }
        }

        // Run the runloop for 15 seconds to let discovery happen
        let deadline = Date().addingTimeInterval(15.0)
        while Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.5))
        }

        // Stop all browsers
        metaBrowser?.stop()
        for (_, browser) in typeBrowsers {
            browser.stop()
        }

        // Report summary
        lock.lock()
        let typeCount = discoveredTypes.count
        let resultCount = allResults.count
        lock.unlock()

        engine.report(module: moduleName, key: "discovery_types_found", value: typeCount)
        engine.report(module: moduleName, key: "discovery_services_found", value: resultCount)
    }

    private func browseType(_ serviceType: String) {
        let browser = NetServiceBrowser()
        browser.delegate = self

        lock.lock()
        typeBrowsers[serviceType] = browser
        lock.unlock()

        browser.searchForServices(ofType: serviceType, inDomain: "local.")
    }

    // MARK: - NetServiceBrowserDelegate

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        if browser === metaBrowser {
            // Meta-query results are service types encoded as service instances
            let serviceType = "\(service.name).\(service.type)"
            lock.lock()
            let isNew = discoveredTypes.insert(serviceType).inserted
            lock.unlock()

            engine.report(module: moduleName, key: "discovered_type", value: serviceType)

            if isNew {
                browseType(serviceType)
            }
        } else {
            // Instance found — resolve it
            engine.report(module: moduleName, key: "found_service",
                          value: ["name": service.name, "type": service.type, "domain": service.domain])

            service.delegate = self
            lock.lock()
            resolvingServices.append(service)
            lock.unlock()

            service.resolve(withTimeout: 5.0)
        }
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        // Service went away during discovery — not critical
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        engine.reportError(module: moduleName, key: "browse_error", error: "\(errorDict)")
    }

    func netServiceBrowserDidStopSearch(_ browser: NetServiceBrowser) {
        // Expected on cleanup
    }

    // MARK: - NetServiceDelegate (resolution)

    func netServiceDidResolveAddress(_ sender: NetService) {
        var info: [String: Any] = [
            "name": sender.name,
            "type": sender.type,
            "domain": sender.domain,
            "port": sender.port
        ]

        if let hostName = sender.hostName {
            info["host"] = hostName
        }

        // Decode TXT record
        if let txtData = sender.txtRecordData() {
            let txtDict = NetService.dictionary(fromTXTRecord: txtData)
            var decodedTxt: [String: String] = [:]
            for (key, value) in txtDict {
                if let str = String(data: value, encoding: .utf8) {
                    decodedTxt[key] = str
                } else {
                    decodedTxt[key] = value.base64EncodedString()
                }
            }
            info["txt"] = decodedTxt
        }

        // Decode addresses
        var addresses: [[String: Any]] = []
        if let addrList = sender.addresses {
            for addrData in addrList {
                addrData.withUnsafeBytes { rawBuffer in
                    guard let saPtr = rawBuffer.baseAddress?.assumingMemoryBound(to: sockaddr.self) else { return }
                    var addrInfo: [String: Any] = [:]

                    if saPtr.pointee.sa_family == sa_family_t(AF_INET) {
                        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                        saPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                            var addr = sin.pointee.sin_addr
                            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
                            addrInfo["family"] = "IPv4"
                            addrInfo["address"] = String(cString: buf)
                            addrInfo["port"] = Int(sin.pointee.sin_port.bigEndian)
                        }
                    } else if saPtr.pointee.sa_family == sa_family_t(AF_INET6) {
                        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                        saPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                            var addr = sin6.pointee.sin6_addr
                            inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                            addrInfo["family"] = "IPv6"
                            addrInfo["address"] = String(cString: buf)
                            addrInfo["port"] = Int(sin6.pointee.sin6_port.bigEndian)
                        }
                    }

                    if !addrInfo.isEmpty {
                        addresses.append(addrInfo)
                    }
                }
            }
        }
        info["addresses"] = addresses

        lock.lock()
        allResults.append(info)
        lock.unlock()

        engine.report(module: moduleName, key: "resolved_service.\(sender.type).\(sender.name)", value: info)
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        engine.reportError(module: moduleName, key: "resolve_error.\(sender.type).\(sender.name)",
                           error: "\(errorDict)")
    }
}
