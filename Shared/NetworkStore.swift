import Foundation

/// Creates, lists and deletes tinc networks in the App Group container.
final class NetworkStore {
    static let shared = NetworkStore()

    private let fileManager = FileManager.default
    private static let activeNetworkKey = "activeNetwork"

    init() {
        try? fileManager.createDirectory(at: AppGroup.networksURL, withIntermediateDirectories: true)
    }

    func networks() -> [TincNetwork] {
        let names = (try? fileManager.contentsOfDirectory(atPath: AppGroup.networksURL.path)) ?? []
        return names
            .filter { !$0.hasPrefix(".") }
            .map(TincNetwork.init(name:))
            .filter { fileManager.fileExists(atPath: $0.tincConfURL.path) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    func network(named name: String) -> TincNetwork? {
        let network = TincNetwork(name: name)
        return fileManager.fileExists(atPath: network.tincConfURL.path) ? network : nil
    }

    /// The network the tunnel connects to. Shared with the extension.
    var activeNetwork: TincNetwork? {
        get {
            if let name = AppGroup.defaults.string(forKey: Self.activeNetworkKey), let network = network(named: name) {
                return network
            }
            return networks().first
        }
        set {
            AppGroup.defaults.set(newValue?.name, forKey: Self.activeNetworkKey)
        }
    }

    /// Mirrors tinc's check_netname(strict): no path separators, control or shell characters.
    static func isValidNetName(_ name: String) -> Bool {
        guard !name.isEmpty, !name.hasPrefix("."), name.count <= 64 else { return false }
        let forbidden = CharacterSet(charactersIn: "/\\ $%<>:`\"|?*").union(.controlCharacters)
        return name.rangeOfCharacter(from: forbidden) == nil
    }

    // MARK: - Creating networks

    struct NewNetwork {
        var netname: String
        var nodeName: String
        /// This device's VPN address and the network's prefix, e.g. 10.20.0.2/24.
        var address: IPAddressRange
        /// Optional public address others can reach this device at.
        var publicAddress: String?
        var port: Int?
        /// Optional nodes to connect to (their host files must be added later).
        var connectTo: [String]
    }

    /// Creates a new network with this device as its first node, like `tinc init`.
    func create(_ spec: NewNetwork) throws -> TincNetwork {
        guard Self.isValidNetName(spec.netname) else {
            throw TincMeshError("Network names cannot contain spaces, slashes or special characters.")
        }
        guard TincConfigFile.isValidNodeName(spec.nodeName) else {
            throw TincMeshError("Device names may only contain letters, digits and underscores.")
        }
        let network = TincNetwork(name: spec.netname)
        guard !fileManager.fileExists(atPath: network.directory.path) else {
            throw TincMeshError("A network named \(spec.netname) already exists.")
        }

        try fileManager.createDirectory(at: network.hostsURL, withIntermediateDirectories: true)
        do {
            var config = TincConfigFile()
            config.append("Name", spec.nodeName)
            for peer in spec.connectTo {
                config.append("ConnectTo", peer)
            }
            try network.saveConfig(config)

            let publicKey = try TincCore.generateKey(privateKeyURL: network.privateKeyURL)

            var host = TincConfigFile()
            if let publicAddress = spec.publicAddress, !publicAddress.isEmpty {
                host.append("Address", publicAddress)
            }
            if let port = spec.port {
                host.append("Port", String(port))
            }
            // Announce just this device's address; the prefix only shapes local routes.
            host.append("Subnet", spec.address.addressString)
            host.append("Ed25519PublicKey", publicKey)
            try network.saveHost(spec.nodeName, host)

            var settings = TunnelSettings()
            settings.addresses = [spec.address.description]
            if !spec.address.isSingleHost {
                settings.routes = [spec.address.network.description]
            }
            try network.saveSettings(settings)
        } catch {
            try? fileManager.removeItem(at: network.directory)
            throw error
        }
        return network
    }

    // MARK: - Invitations

    /// Joins a network with a `tinc invite` URL. Blocks on network I/O; call off the main thread.
    func join(invitation: String, netname requestedName: String?) throws -> TincNetwork {
        let staging = AppGroup.networksURL.appendingPathComponent(".join-\(UUID().uuidString)", isDirectory: true)
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: staging) }

        let result = try TincCore.join(directory: staging, invitation: invitation)

        var netname = requestedName?.trimmingCharacters(in: .whitespaces) ?? ""
        if netname.isEmpty { netname = result.netname }
        if netname.isEmpty { netname = result.name }
        netname = uniqueNetName(netname)

        // Apply what tinc-up would have done from the invitation's Ifconfig/Route lines.
        var settings = TunnelSettings()
        settings.addresses = result.ifconfig.filter { IPAddressRange($0) != nil }
        settings.routes = result.routes.filter { IPAddressRange($0) != nil }
        let network = TincNetwork(name: netname)
        try fileManager.moveItem(at: staging, to: network.directory)
        try network.saveSettings(settings)
        return network
    }

    private func uniqueNetName(_ base: String) -> String {
        let cleaned = Self.isValidNetName(base) ? base : "tinc"
        var candidate = cleaned
        var counter = 2
        while fileManager.fileExists(atPath: TincNetwork(name: candidate).directory.path) {
            candidate = "\(cleaned)-\(counter)"
            counter += 1
        }
        return candidate
    }

    /// Creates an invitation for a new device. `address` is how the invitee reaches
    /// this device (host or host:port); `vpnAddress` optionally assigns its IP.
    func invite(network: TincNetwork, invitee: String, address: String, vpnAddress: IPAddressRange?) throws -> String {
        var extra: [String] = []
        if let vpnAddress {
            extra.append("Ifconfig = \(vpnAddress.description)")
            extra.append("Subnet = \(vpnAddress.addressString)")
        }
        return try TincCore.invite(
            directory: network.directory,
            netname: network.name,
            invitee: invitee,
            address: address,
            extraLines: extra.isEmpty ? nil : extra.joined(separator: "\n"))
    }

    // MARK: - Hosts

    /// Adds or replaces another node's host file (e.g. one shared from a desktop machine).
    func importHost(name: String, contents: String, into network: TincNetwork) throws {
        guard TincConfigFile.isValidNodeName(name) else {
            throw TincMeshError("“\(name)” is not a valid tinc node name.")
        }
        if name == network.nodeName {
            throw TincMeshError("That is this device's own host file.")
        }
        let config = TincConfigFile(text: contents)
        guard config.value("Ed25519PublicKey") != nil || contents.contains("BEGIN ED25519 PUBLIC KEY") else {
            throw TincMeshError("The host file has no Ed25519 public key. This app only speaks tinc 1.1's SPTPS protocol.")
        }
        try fileManager.createDirectory(at: network.hostsURL, withIntermediateDirectories: true)
        try config.write(to: network.hostURL(name))
    }

    func removeHost(name: String, from network: TincNetwork) throws {
        try fileManager.removeItem(at: network.hostURL(name))
    }

    func delete(_ network: TincNetwork) throws {
        try fileManager.removeItem(at: network.directory)
        if AppGroup.defaults.string(forKey: Self.activeNetworkKey) == network.name {
            AppGroup.defaults.removeObject(forKey: Self.activeNetworkKey)
        }
    }

    func rename(_ network: TincNetwork, to newName: String) throws -> TincNetwork {
        guard Self.isValidNetName(newName) else {
            throw TincMeshError("Network names cannot contain spaces, slashes or special characters.")
        }
        let renamed = TincNetwork(name: newName)
        try fileManager.moveItem(at: network.directory, to: renamed.directory)
        if AppGroup.defaults.string(forKey: Self.activeNetworkKey) == network.name {
            activeNetwork = renamed
        }
        return renamed
    }
}
