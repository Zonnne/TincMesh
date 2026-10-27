import Foundation

/// One tinc network: a directory holding the same files tinc uses on any
/// other platform (`tinc.conf`, `hosts/`, `ed25519_key.priv`), so it can be
/// copied to or from a desktop installation unchanged.
struct TincNetwork: Hashable {
    /// The netname, which is also the directory name.
    let name: String

    var directory: URL { AppGroup.networksURL.appendingPathComponent(name, isDirectory: true) }
    var tincConfURL: URL { directory.appendingPathComponent("tinc.conf") }
    var hostsURL: URL { directory.appendingPathComponent("hosts", isDirectory: true) }
    var privateKeyURL: URL { directory.appendingPathComponent("ed25519_key.priv") }
    var settingsURL: URL { directory.appendingPathComponent(TunnelSettings.fileName) }

    func hostURL(_ node: String) -> URL {
        hostsURL.appendingPathComponent(node)
    }

    func loadConfig() -> TincConfigFile? {
        try? TincConfigFile(contentsOf: tincConfURL)
    }

    func saveConfig(_ config: TincConfigFile) throws {
        try config.write(to: tincConfURL)
    }

    func loadHost(_ node: String) -> TincConfigFile? {
        try? TincConfigFile(contentsOf: hostURL(node))
    }

    func saveHost(_ node: String, _ config: TincConfigFile) throws {
        try config.write(to: hostURL(node))
    }

    /// This device's node name (`Name` in tinc.conf).
    var nodeName: String? {
        loadConfig()?.value("Name")
    }

    /// Names of all nodes we have a host file for, including ourselves.
    func hostNames() -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: hostsURL.path)) ?? []
        return files.filter(TincConfigFile.isValidNodeName).sorted {
            $0.localizedStandardCompare($1) == .orderedAscending
        }
    }

    func loadSettings() -> TunnelSettings {
        guard let data = try? Data(contentsOf: settingsURL),
              let settings = try? JSONDecoder().decode(TunnelSettings.self, from: data) else {
            return TunnelSettings()
        }
        return settings
    }

    func saveSettings(_ settings: TunnelSettings) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(settings).write(to: settingsURL, options: .atomic)
    }

    /// IP Subnets from a host file, ignoring MAC subnets.
    func subnets(of node: String) -> [IPAddressRange] {
        loadHost(node)?.values("Subnet").compactMap(IPAddressRange.init) ?? []
    }

    /// The interface addresses to configure: explicit settings first, otherwise
    /// the single-host Subnets this node announces (e.g. `Subnet = 10.0.0.5/32`).
    func interfaceAddresses(_ settings: TunnelSettings) -> [IPAddressRange] {
        let explicit = settings.addresses.compactMap(IPAddressRange.init)
        if !explicit.isEmpty {
            return explicit
        }
        guard let me = nodeName else { return [] }
        return subnets(of: me).filter(\.isSingleHost)
    }

    /// Routes known before tinc starts: configured routes plus Subnets from
    /// other nodes' host files. Subnets learned from the mesh are added live
    /// by the tunnel extension.
    func staticRoutes(_ settings: TunnelSettings) -> [IPAddressRange] {
        var routes = settings.routes.compactMap(IPAddressRange.init)
        if settings.routePeerSubnets {
            let me = nodeName
            for host in hostNames() where host != me {
                routes += subnets(of: host)
            }
        }
        return routes
    }

    /// Problems that would stop the network from working on iOS.
    func validate() -> String? {
        guard let config = loadConfig() else { return "tinc.conf is missing or unreadable." }
        guard let me = config.value("Name") else { return "tinc.conf has no Name." }
        if let mode = config.value("Mode"), mode.lowercased() != "router" {
            return "Mode = \(mode) is not supported on iOS; only router mode is available."
        }
        if !FileManager.default.fileExists(atPath: hostURL(me).path) {
            return "The host file for \(me) is missing."
        }
        if !FileManager.default.fileExists(atPath: privateKeyURL.path),
           config.value("Ed25519PrivateKeyFile") == nil {
            return "ed25519_key.priv is missing."
        }
        if interfaceAddresses(loadSettings()).isEmpty {
            return "This device has no VPN address. Add a single-host Subnet to its host file or set an address in Settings."
        }
        return nil
    }
}
