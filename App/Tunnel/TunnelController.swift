import NetworkExtension

extension Notification.Name {
    /// Posted on the main queue whenever the VPN status or configuration changes.
    static let tunnelStatusDidChange = Notification.Name("TincMeshTunnelStatusDidChange")
}

/// Owns the app's single NETunnelProviderManager (the entry under
/// Settings > VPN) and talks to the running extension.
final class TunnelController {
    static let shared = TunnelController()

    private(set) var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    private var extensionBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "com.example.tincmesh") + ".PacketTunnel"
    }

    var status: NEVPNStatus {
        manager?.connection.status ?? .invalid
    }

    var isActive: Bool {
        [.connected, .connecting, .reasserting].contains(status)
    }

    /// The network the VPN configuration points at.
    var configuredNetworkName: String? {
        (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["network"] as? String
    }

    var isOnDemandEnabled: Bool {
        manager?.isOnDemandEnabled ?? false
    }

    func load(completion: (() -> Void)? = nil) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    NSLog("TincMesh: loading VPN configuration failed: %@", error.localizedDescription)
                }
                self.setManager(managers?.first)
                completion?()
            }
        }
    }

    private func setManager(_ manager: NETunnelProviderManager?) {
        self.manager = manager
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusObserver = manager.map { manager in
            NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main) { _ in
                NotificationCenter.default.post(name: .tunnelStatusDidChange, object: nil)
            }
        }
        NotificationCenter.default.post(name: .tunnelStatusDidChange, object: nil)
    }

    /// Points the VPN configuration at `network` and starts it.
    func connect(to network: TincNetwork, completion: @escaping (Error?) -> Void) {
        if let problem = network.validate() {
            completion(TincMeshError(problem))
            return
        }
        NetworkStore.shared.activeNetwork = network

        let manager = self.manager ?? NETunnelProviderManager()
        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionBundleIdentifier
        proto.serverAddress = "tinc: \(network.name)"
        proto.providerConfiguration = ["network": network.name]
        manager.protocolConfiguration = proto
        manager.localizedDescription = "TincMesh"
        manager.isEnabled = true

        let switching = configuredNetworkName != nil && configuredNetworkName != network.name && isActive
        save(manager) { [weak self] error in
            guard let self else { return }
            if let error {
                completion(error)
                return
            }
            if switching {
                manager.connection.stopVPNTunnel()
                // Give the extension a moment to tear down before starting the new network.
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    completion(self.start(manager, network: network))
                }
            } else {
                completion(self.start(manager, network: network))
            }
        }
    }

    private func start(_ manager: NETunnelProviderManager, network: TincNetwork) -> Error? {
        do {
            try manager.connection.startVPNTunnel(options: ["network": network.name as NSString])
            return nil
        } catch {
            return error
        }
    }

    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Restarts the tunnel if it is running `network`, to apply interface settings.
    func reconnectIfActive(_ network: TincNetwork) {
        guard isActive, configuredNetworkName == network.name else { return }
        disconnect()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            self.connect(to: network) { error in
                if let error { NSLog("TincMesh: reconnect failed: %@", error.localizedDescription) }
            }
        }
    }

    /// VPN On Demand: keep the tunnel up whenever there is a network, like an "always on" VPN.
    func setOnDemand(_ enabled: Bool, completion: @escaping (Error?) -> Void) {
        guard let manager else {
            completion(TincMeshError("Connect once before enabling Always On."))
            return
        }
        manager.onDemandRules = enabled ? [NEOnDemandRuleConnect()] : []
        manager.isOnDemandEnabled = enabled
        save(manager, completion: completion)
    }

    func removeConfiguration(completion: @escaping () -> Void) {
        guard let manager else {
            completion()
            return
        }
        manager.removeFromPreferences { [weak self] _ in
            DispatchQueue.main.async {
                self?.setManager(nil)
                completion()
            }
        }
    }

    private func save(_ manager: NETunnelProviderManager, completion: @escaping (Error?) -> Void) {
        manager.saveToPreferences { [weak self] error in
            if let error {
                DispatchQueue.main.async { completion(error) }
                return
            }
            // A freshly saved configuration must be reloaded before it can be started.
            manager.loadFromPreferences { error in
                DispatchQueue.main.async {
                    self?.setManager(manager)
                    completion(error)
                }
            }
        }
    }

    // MARK: - Talking to the extension

    func send(_ command: TunnelCommand, completion: ((Data?) -> Void)? = nil) {
        guard let session = manager?.connection as? NETunnelProviderSession, status == .connected else {
            completion?(nil)
            return
        }
        do {
            try session.sendProviderMessage(Data(command.rawValue.utf8)) { data in
                DispatchQueue.main.async { completion?(data) }
            }
        } catch {
            completion?(nil)
        }
    }

    /// Fetches tinc's view of the mesh from the extension; nil when disconnected.
    func fetchStatus(completion: @escaping (MeshStatus?) -> Void) {
        send(.status) { data in
            completion(data.flatMap { $0.isEmpty ? nil : MeshStatus.decode($0) })
        }
    }

    /// After editing tinc.conf or host files: let a running tinc pick them up.
    func reloadIfActive(_ network: TincNetwork) {
        if configuredNetworkName == network.name {
            send(.reload)
        }
    }
}

extension NEVPNStatus {
    var displayName: String {
        switch self {
        case .invalid: return "Not configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        @unknown default: return "Unknown"
        }
    }
}
