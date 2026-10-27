import Foundation

/// Messages from the app to the running tunnel (NETunnelProviderSession.sendProviderMessage).
enum TunnelCommand: String, Codable {
    /// Reply: the MeshStatus JSON from tinc, or empty data if tinc is not running.
    case status
    /// Reconnect now (like `tinc retry`).
    case retry
    /// Re-read configuration (like `tinc reload`), e.g. after adding a host or invitation.
    case reload
    /// Re-read rules.conf and apply it without reconnecting.
    case reloadRules
}

/// A snapshot of tinc's view of the mesh, produced by tinc_ios_status_json().
struct MeshStatus: Decodable {
    struct Node: Decodable, Hashable {
        let name: String
        let myself: Bool
        let reachable: Bool
        let validkey: Bool
        let indirect: Bool
        let udpConfirmed: Bool
        let sptps: Bool
        let metaConnection: Bool
        let via: String?
        let nexthop: String?
        let distance: Int
        let address: String?
        let port: String?
        let options: Int
        let compression: Int
        let mtu: Int
        let minmtu: Int
        let maxmtu: Int
        /// Microseconds, or -1 when no UDP probe reply has been seen.
        let udpPingRtt: Int
        let lastStateChange: Int
        let inPackets: Int64
        let inBytes: Int64
        let outPackets: Int64
        let outBytes: Int64
        let subnets: [String]

        enum Path: Equatable {
            case myself
            case offline
            /// UDP straight to the node.
            case direct
            /// Packets are forwarded by another node (tinc's equivalent of a relay).
            case relayed(via: String)
            /// No working UDP path yet; packets go over the TCP meta connection.
            case tcp(via: String)
        }

        var path: Path {
            if myself { return .myself }
            if !reachable { return .offline }
            if let via, via != name { return .relayed(via: via) }
            if udpConfirmed { return .direct }
            return .tcp(via: nexthop ?? name)
        }

        var rttMilliseconds: Double? {
            udpPingRtt >= 0 ? Double(udpPingRtt) / 1000 : nil
        }

        var ipSubnets: [IPAddressRange] {
            subnets.compactMap(IPAddressRange.init)
        }
    }

    struct Edge: Decodable, Hashable {
        let from: String
        let to: String
        let address: String?
        let port: String?
        let weight: Int
        let options: Int
    }

    struct Connection: Decodable, Hashable {
        let name: String
        let hostname: String
        let outgoing: Bool
        let active: Bool
        let connecting: Bool
    }

    let version: String
    let name: String?
    let port: String?
    let now: Int
    let nodes: [Node]
    let edges: [Edge]
    let connections: [Connection]
    let policy: PolicyStatus?

    static func decode(_ data: Data) -> MeshStatus? {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try? decoder.decode(MeshStatus.self, from: data)
    }

    var myself: Node? {
        nodes.first(where: \.myself)
    }

    func node(named name: String) -> Node? {
        nodes.first { $0.name == name }
    }
}
