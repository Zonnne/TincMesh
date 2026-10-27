import Foundation

/// Rule-based routing: Shadowrocket-style rules that send chosen sites
/// through chosen tinc nodes (TincCore/ios/policy.c does the routing).
enum PolicyRules {
    static let fileName = "rules.conf"

    static let template = """
    # TincMesh rules: send sites through chosen tinc nodes.
    # A policy is a node name, a group, DIRECT or REJECT. The first matching rule wins.
    # Exit nodes need "Forwarding = kernel" in tinc.conf, IP forwarding and NAT.

    [General]
    # Resolver for names matched by a rule, queried through that rule's node.
    dns-server = 1.1.1.1
    # Resolver for all other names, queried directly from this device.
    direct-dns-server = 1.1.1.1

    [Proxy Group]
    # fallback = first reachable node, url-test = lowest round trip, select = first member
    # streaming = fallback, node_x, node_y

    [Rule]
    # DOMAIN-SUFFIX,netflix.com,node_x
    # DOMAIN,github.com,node_y
    # DOMAIN-KEYWORD,google,streaming
    # IP-CIDR,203.0.113.0/24,node_y
    # DOMAIN-SUFFIX,ads.example,REJECT
    FINAL,DIRECT

    """

    /// What tinc needs the tunnel to capture for a set of rules.
    struct Summary: Decodable, Equatable {
        let dnsAddress: String
        let fakeRange: String
        let captureAllDns: Bool
        let defaultRoute: Bool
        let matchDomains: [String]
        let includeRoutes: [String]
        let excludeRoutes: [String]
        let groups: [String]
        let nodes: [String]
        let warnings: [String]
        let rules: Int
        let final: String
    }

    /// The rules file as tinc should see it: the user's text, plus the mesh's
    /// own DNS server and domains from the VPN settings unless the file sets them.
    static func effectiveText(_ text: String, settings: TunnelSettings) -> String {
        var extra: [String] = []
        let lower = text.lowercased()
        if let server = settings.dnsServers.first, !lower.contains("mesh-dns-server") {
            extra.append("mesh-dns-server = \(server)")
            if !settings.searchDomains.isEmpty, !lower.contains("mesh-domains") {
                extra.append("mesh-domains = \(settings.searchDomains.joined(separator: ", "))")
            }
        }
        guard !extra.isEmpty else { return text }
        // Appended, so line numbers in error messages match the user's file.
        return text + (text.hasSuffix("\n") ? "" : "\n") + "[General]\n" + extra.joined(separator: "\n") + "\n"
    }
}

extension TincNetwork {
    func loadRules() -> String? {
        try? String(contentsOf: rulesURL, encoding: .utf8)
    }

    /// The rules tinc should use, or nil when rule-based routing is off.
    func activeRules(_ settings: TunnelSettings) -> String? {
        guard settings.rulesEnabled, let text = loadRules() else { return nil }
        return PolicyRules.effectiveText(text, settings: settings)
    }
}

/// Live rule-engine counters from the status snapshot.
struct PolicyStatus: Decodable, Hashable {
    struct Group: Decodable, Hashable {
        let name: String
        let selected: String?
    }

    let enabled: Bool
    let rules: Int?
    let flows: Int?
    let fakeIps: Int?
    let dnsPending: Int?
    let dnsQueries: Int?
    let dnsFake: Int?
    let dnsDirect: Int?
    let dnsRejected: Int?
    let dnsFailed: Int?
    let routedPackets: Int?
    let rejectedPackets: Int?
    let groups: [Group]?
}
