import Foundation
import Network

final class NetworkServer {
    static let shared = NetworkServer()

    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private let serverQueue = DispatchQueue(label: "com.tvosrecon.server", qos: .utility)
    private let connectionsLock = NSLock()

    private(set) var port: UInt16 = 9100
    private(set) var isListening: Bool = false
    private(set) var advertisedName: String = ""
    private(set) var localAddress: String = "unknown"

    private init() {}

    func start(port: UInt16 = 9100) {
        self.port = port

        let params = NWParameters.tcp
        params.includePeerToPeer = true

        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }

        do {
            listener = try NWListener(using: params, on: nwPort)
        } catch {
            NSLog("TVOSRecon: Failed to create listener: \(error)")
            return
        }

        let service = NWListener.Service(name: "TVOSRecon", type: "_tvosrecon._tcp")
        listener?.service = service
        advertisedName = "TVOSRecon"

        listener?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.isListening = true
                self?.localAddress = self?.getLocalIPAddress() ?? "unknown"
                NSLog("TVOSRecon: Server listening on \(self?.localAddress ?? "?"):\(port)")
            case .failed(let error):
                NSLog("TVOSRecon: Listener failed: \(error)")
                self?.isListening = false
            case .cancelled:
                self?.isListening = false
            default:
                break
            }
        }

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleNewConnection(connection)
        }

        listener?.start(queue: serverQueue)
    }

    func stop() {
        listener?.cancel()
        connectionsLock.lock()
        for conn in connections {
            conn.cancel()
        }
        connections.removeAll()
        connectionsLock.unlock()
        isListening = false
    }

    func send(_ jsonLine: String) {
        let line = jsonLine + "\n"
        guard let data = line.data(using: .utf8) else { return }

        connectionsLock.lock()
        let activeConnections = connections
        connectionsLock.unlock()

        for connection in activeConnections {
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    NSLog("TVOSRecon: Send error: \(error)")
                }
            })
        }
    }

    private func handleNewConnection(_ connection: NWConnection) {
        NSLog("TVOSRecon: New client connection")

        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                NSLog("TVOSRecon: Client connected")
            case .failed(let error):
                NSLog("TVOSRecon: Connection failed: \(error)")
                self?.removeConnection(connection)
            case .cancelled:
                self?.removeConnection(connection)
            default:
                break
            }
        }

        connectionsLock.lock()
        connections.append(connection)
        connectionsLock.unlock()

        connection.start(queue: serverQueue)
    }

    private func removeConnection(_ connection: NWConnection) {
        connectionsLock.lock()
        connections.removeAll { $0 === connection }
        connectionsLock.unlock()
    }

    private func getLocalIPAddress() -> String? {
        var addresses: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let current = ptr {
            let flags = Int32(current.pointee.ifa_flags)
            let addr = current.pointee.ifa_addr.pointee

            if (flags & (IFF_UP | IFF_RUNNING)) != 0 && addr.sa_family == sa_family_t(AF_INET) {
                let name = String(cString: current.pointee.ifa_name)
                if name != "lo0" {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(current.pointee.ifa_addr, socklen_t(addr.sa_len),
                                   &hostname, socklen_t(hostname.count),
                                   nil, 0, NI_NUMERICHOST) == 0 {
                        addresses.append(String(cString: hostname))
                    }
                }
            }
            ptr = current.pointee.ifa_next
        }

        return addresses.first
    }

    var connectionCount: Int {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        return connections.count
    }

    var displayAddress: String {
        if let addr = getLocalIPAddress() {
            return "\(addr):\(port)"
        }
        return "0.0.0.0:\(port)"
    }
}
