import Foundation

/// Per-network iOS settings, stored as `ios.json` next to `tinc.conf`.
///
/// On other platforms the tinc-up script configures the interface; iOS
/// cannot run scripts, so the equivalent lives here and is applied through
/// NEPacketTunnelNetworkSettings. Addresses and routes are CIDR strings.
struct TunnelSettings: Codable, Equatable {
    /// Interface addresses. Empty means "use this node's single-host Subnets".
    var addresses: [String] = []
    /// Extra routes into the VPN, in addition to peers' Subnets.
    var routes: [String] = []
    var dnsServers: [String] = []
    var searchDomains: [String] = []
    var mtu: Int = 1400
    /// Route every Subnet announced by peers through the tunnel, updated live.
    var routePeerSubnets: Bool = true
    /// Accept a default route (0.0.0.0/0 or ::/0) announced by a peer, like an exit node.
    var useExitNode: Bool = false
    /// tinc debug level (0 = errors and basic status ... 5 = everything).
    var logLevel: Int = 1
    /// Route sites through chosen nodes using the rules in rules.conf (see PolicyRules).
    var rulesEnabled: Bool = false

    static let fileName = "ios.json"

    init() {}

    init(from decoder: Decoder) throws {
        // Every field is optional so older or hand-written files keep loading.
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = TunnelSettings()
        addresses = try c.decodeIfPresent([String].self, forKey: .addresses) ?? defaults.addresses
        routes = try c.decodeIfPresent([String].self, forKey: .routes) ?? defaults.routes
        dnsServers = try c.decodeIfPresent([String].self, forKey: .dnsServers) ?? defaults.dnsServers
        searchDomains = try c.decodeIfPresent([String].self, forKey: .searchDomains) ?? defaults.searchDomains
        mtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? defaults.mtu
        routePeerSubnets = try c.decodeIfPresent(Bool.self, forKey: .routePeerSubnets) ?? defaults.routePeerSubnets
        useExitNode = try c.decodeIfPresent(Bool.self, forKey: .useExitNode) ?? defaults.useExitNode
        logLevel = try c.decodeIfPresent(Int.self, forKey: .logLevel) ?? defaults.logLevel
        rulesEnabled = try c.decodeIfPresent(Bool.self, forKey: .rulesEnabled) ?? defaults.rulesEnabled
    }
}
