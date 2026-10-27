import Network
import NetworkExtension
import os.log

/// Hosts a tinc 1.1 node inside the Network Extension.
///
/// Startup: load the selected network from the App Group, apply interface
/// addresses and routes (what tinc-up does elsewhere), create the packet
/// socketpair, then run tinc on its own thread. Routes to Subnets learned
/// from the mesh are kept up to date while connected. With rule-based
/// routing on, DNS for matching names and the fake address range are sent
/// into the tunnel, where tinc's policy engine picks the node for each site.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "TincMesh", category: "tunnel")
    private let queue = DispatchQueue(label: "tincmesh.provider")

    private var network: TincNetwork?
    private var settings = TunnelSettings()
    private var runner: TincRunner?
    private var bridge: PacketBridge?
    private var pathMonitor: NWPathMonitor?
    private var lastPathSignature: String?
    private var routeTimer: DispatchSourceTimer?
    private var appliedRoutes: [IPAddressRange] = []
    /// What the active rules need captured; nil when rule-based routing is off.
    private var policy: PolicyRules.Summary?
    private var startCompletion: ((Error?) -> Void)?
    private var stopping = false

    private static let routeRefreshInterval: TimeInterval = 10

    // MARK: - Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let configured = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["network"] as? String
        let requested = options?["network"] as? String
        guard let name = requested ?? configured ?? NetworkStore.shared.activeNetwork?.name,
              let network = NetworkStore.shared.network(named: name) else {
            completionHandler(TincMeshError("No tinc network is configured. Open TincMesh to join or create one."))
            return
        }
        if let problem = network.validate() {
            completionHandler(TincMeshError(problem))
            return
        }

        self.network = network
        settings = network.loadSettings()
        os_log("Starting network %{public}@ with tinc %{public}@", log: log, type: .info, network.name, TincCore.version)

        do {
            try loadRules()
        } catch {
            completionHandler(TincMeshError("The routing rules have an error: \(error.localizedDescription)"))
            return
        }

        let routes = network.staticRoutes(settings).filter { settings.useExitNode || !$0.isDefaultRoute }
        let networkSettings = makeNetworkSettings(routes: routes)
        appliedRoutes = routes

        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            guard let self else { return }
            if let error {
                completionHandler(error)
                return
            }
            self.queue.async { self.startTinc(network: network, completionHandler: completionHandler) }
        }
    }

    private func startTinc(network: TincNetwork, completionHandler: @escaping (Error?) -> Void) {
        let bridge: PacketBridge
        do {
            bridge = try PacketBridge(flow: packetFlow)
        } catch {
            completionHandler(error)
            return
        }
        self.bridge = bridge
        startCompletion = completionHandler

        let runner = TincRunner()
        self.runner = runner
        runner.start(
            confbase: network.directory,
            logURL: AppGroup.logURL,
            tunFD: bridge.tincFD,
            debugLevel: Int32(settings.logLevel),
            onReady: { [weak self] in
                self?.queue.async { self?.tincDidStart() }
            },
            onExit: { [weak self] status in
                self?.queue.async { self?.tincDidExit(status: status) }
            })
    }

    private func tincDidStart() {
        bridge?.start()
        startPathMonitor()
        startRouteTimer()
        startCompletion?(nil)
        startCompletion = nil
    }

    private func tincDidExit(status: Int32) {
        os_log("tinc exited with status %d", log: log, type: .info, status)
        bridge?.stop()
        if let completion = startCompletion {
            startCompletion = nil
            completion(TincMeshError("tinc could not start. Check the log in TincMesh for details."))
        } else if !stopping {
            // tinc stopped on its own (fatal error); tear the tunnel down so iOS shows it.
            cancelTunnelWithError(TincMeshError("tinc stopped unexpectedly (status \(status))."))
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping, reason %ld", log: log, type: .info, reason.rawValue)
        queue.async {
            self.stopping = true
            self.pathMonitor?.cancel()
            self.pathMonitor = nil
            self.routeTimer?.cancel()
            self.routeTimer = nil
            let runner = self.runner
            DispatchQueue.global(qos: .userInitiated).async {
                runner?.stop()
                self.queue.async {
                    self.bridge?.stop()
                    self.runner = nil
                    self.bridge = nil
                    completionHandler()
                }
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
        // Sockets and NAT mappings are often stale after sleep.
        runner?.retry()
    }

    // MARK: - Messages from the app

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let command = TunnelCommand(rawValue: String(decoding: messageData, as: UTF8.self))
        let runner = queue.sync { self.runner }
        DispatchQueue.global(qos: .userInitiated).async {
            switch command {
            case .status:
                completionHandler?(runner?.statusJSON() ?? Data())
            case .retry:
                runner?.retry()
                completionHandler?(nil)
            case .reload:
                runner?.reload()
                self.queue.asyncAfter(deadline: .now() + 1) { self.refreshRoutes() }
                completionHandler?(nil)
            case .reloadRules:
                self.queue.async {
                    self.reloadRules()
                    completionHandler?(nil)
                }
            case nil:
                completionHandler?(nil)
            }
        }
    }

    // MARK: - Rules

    /// Validates the network's rules and hands them to tinc (or turns rules off).
    private func loadRules() throws {
        guard let network, let text = network.activeRules(settings) else {
            policy = nil
            try TincCore.setRules(nil)
            return
        }
        let summary = try TincCore.checkRules(text)
        guard network.interfaceAddresses(settings).contains(where: { $0.family == .v4 }) else {
            throw TincMeshError("Rule-based routing needs an IPv4 VPN address.")
        }
        try TincCore.setRules(text)
        policy = summary
        os_log("Rules: %d, FINAL %{public}@", log: log, type: .info, summary.rules, summary.final)
    }

    /// Applies edited rules to the running tunnel without reconnecting.
    private func reloadRules() {
        guard let network, !stopping else { return }
        settings = network.loadSettings()
        do {
            try loadRules()
        } catch {
            os_log("Keeping previous rules: %{public}@", log: log, type: .error, error.localizedDescription)
            return
        }
        setTunnelNetworkSettings(makeNetworkSettings(routes: appliedRoutes)) { [weak self] error in
            if let error, let self {
                os_log("Could not apply rule routes: %{public}@", log: self.log, type: .error, error.localizedDescription)
            }
        }
    }

    // MARK: - Network changes

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.pathDidChange(path)
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private func pathDidChange(_ path: Network.NWPath) {
        // Ignore our own utun interface; only react to changes in the underlying network.
        let interfaces = path.availableInterfaces
            .filter { $0.type != .other }
            .map { "\($0.name):\($0.type)" }
        let signature = "\(path.status):\(interfaces.joined(separator: ","))"
        defer { lastPathSignature = signature }
        guard let previous = lastPathSignature, previous != signature, path.status == .satisfied else { return }
        os_log("Network path changed (%{public}@), reconnecting", log: log, type: .info, signature)
        runner?.retry()
    }

    // MARK: - Routes

    private func startRouteTimer() {
        guard settings.routePeerSubnets else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: Self.routeRefreshInterval)
        timer.setEventHandler { [weak self] in self?.refreshRoutes() }
        timer.resume()
        routeTimer = timer
    }

    /// Adds routes for Subnets announced by reachable peers that are not covered yet.
    private func refreshRoutes() {
        guard settings.routePeerSubnets, !stopping, let network, let runner else { return }
        DispatchQueue.global(qos: .utility).async {
            guard let data = runner.statusJSON(), let status = MeshStatus.decode(data) else { return }
            let own = Set(network.interfaceAddresses(self.settings).map(\.network))
            var routes = network.staticRoutes(self.settings)
            for node in status.nodes where node.reachable && !node.myself {
                routes += node.ipSubnets
            }
            routes = routes.filter { (self.settings.useExitNode || !$0.isDefaultRoute) && !own.contains($0.network) }
            self.queue.async { self.applyRoutesIfChanged(routes) }
        }
    }

    private func applyRoutesIfChanged(_ routes: [IPAddressRange]) {
        let normalized = Self.unique(routes.map(\.network))
        guard Set(normalized) != Set(appliedRoutes.map(\.network)), !stopping else { return }
        os_log("Updating routes: %{public}@", log: log, type: .info, normalized.map(\.description).joined(separator: ", "))
        appliedRoutes = normalized
        setTunnelNetworkSettings(makeNetworkSettings(routes: normalized)) { [weak self] error in
            if let error, let self {
                os_log("Could not update routes: %{public}@", log: self.log, type: .error, error.localizedDescription)
            }
        }
    }

    private static func unique(_ ranges: [IPAddressRange]) -> [IPAddressRange] {
        var seen = Set<IPAddressRange>()
        return ranges.filter { seen.insert($0).inserted }
    }

    // MARK: - Interface configuration (what tinc-up does on other platforms)

    private func makeNetworkSettings(routes: [IPAddressRange]) -> NEPacketTunnelNetworkSettings {
        guard let network else { return NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1") }
        let addresses = network.interfaceAddresses(settings)

        // A mesh has no single remote endpoint; this address is informational only.
        let result = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        result.mtu = NSNumber(value: settings.mtu)

        // The prefix of an interface address (e.g. 10.0.0.5/24) also routes that network.
        var included = routes + addresses.filter { !$0.isSingleHost }
        var excluded: [IPAddressRange] = []
        if let policy {
            // Fake addresses for rule-matched names (and the DNS responder), plus IP-CIDR rules.
            included += ([policy.fakeRange] + policy.includeRoutes).compactMap(IPAddressRange.init)
            if policy.defaultRoute {
                included += ["0.0.0.0/0", "::/0"].compactMap(IPAddressRange.init)
            }
            excluded = policy.excludeRoutes.compactMap(IPAddressRange.init)
        }
        let allRoutes = Self.unique(included.map(\.network))

        let v4Addresses = addresses.filter { $0.family == .v4 }
        if !v4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(addresses: v4Addresses.map(\.addressString),
                                      subnetMasks: v4Addresses.map(\.subnetMaskString))
            ipv4.includedRoutes = allRoutes.filter { $0.family == .v4 }.map { range in
                range.isDefaultRoute
                    ? NEIPv4Route.default()
                    : NEIPv4Route(destinationAddress: range.addressString, subnetMask: range.subnetMaskString)
            }
            ipv4.excludedRoutes = excluded.filter { $0.family == .v4 }.map {
                NEIPv4Route(destinationAddress: $0.network.addressString, subnetMask: $0.subnetMaskString)
            }
            result.ipv4Settings = ipv4
        }

        let v6Addresses = addresses.filter { $0.family == .v6 }
        if !v6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: v6Addresses.map(\.addressString),
                                      networkPrefixLengths: v6Addresses.map { NSNumber(value: $0.prefix) })
            ipv6.includedRoutes = allRoutes.filter { $0.family == .v6 }.map { range in
                range.isDefaultRoute
                    ? NEIPv6Route.default()
                    : NEIPv6Route(destinationAddress: range.addressString, networkPrefixLength: NSNumber(value: range.prefix))
            }
            ipv6.excludedRoutes = excluded.filter { $0.family == .v6 }.map {
                NEIPv6Route(destinationAddress: $0.network.addressString, networkPrefixLength: NSNumber(value: $0.prefix))
            }
            result.ipv6Settings = ipv6
        }

        if let policy, policy.captureAllDns || !policy.matchDomains.isEmpty {
            // tinc's policy engine answers these queries (and forwards the rest itself).
            let dns = NEDNSSettings(servers: [policy.dnsAddress])
            dns.matchDomains = policy.captureAllDns ? [""] : policy.matchDomains
            if !settings.searchDomains.isEmpty {
                dns.searchDomains = settings.searchDomains
            }
            result.dnsSettings = dns
        } else if !settings.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: settings.dnsServers)
            if !settings.searchDomains.isEmpty {
                dns.searchDomains = settings.searchDomains
                // Without an exit node, only send queries for the mesh's domains to its servers.
                dns.matchDomains = settings.useExitNode ? [""] : settings.searchDomains
            }
            result.dnsSettings = dns
        }

        return result
    }
}
