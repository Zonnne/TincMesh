import Foundation

/// An IPv4 or IPv6 address with a prefix length, e.g. `10.0.0.5/24` or `fd00::1/64`.
///
/// Accepts tinc's Subnet syntax too: the prefix may be omitted (meaning a
/// single host) and a `#weight` suffix is ignored. MAC subnets are rejected.
struct IPAddressRange: Hashable, CustomStringConvertible {
    enum Family {
        case v4, v6
    }

    let family: Family
    let bytes: [UInt8]
    let prefix: Int

    init?(_ string: String) {
        var text = string.trimmingCharacters(in: .whitespaces)
        if let hash = text.firstIndex(of: "#") {
            text = String(text[..<hash])
        }
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        let addressText = String(parts[0])

        if let v4 = Self.parse(addressText, family: AF_INET, length: 4) {
            family = .v4
            bytes = v4
        } else if let v6 = Self.parse(addressText, family: AF_INET6, length: 16) {
            family = .v6
            bytes = v6
        } else {
            return nil
        }

        let maxPrefix = bytes.count * 8
        if parts.count == 2 {
            guard let value = Int(parts[1]), (0...maxPrefix).contains(value) else { return nil }
            prefix = value
        } else {
            prefix = maxPrefix
        }
    }

    private init(family: Family, bytes: [UInt8], prefix: Int) {
        self.family = family
        self.bytes = bytes
        self.prefix = prefix
    }

    private static func parse(_ text: String, family: Int32, length: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: length)
        let ok = buffer.withUnsafeMutableBytes { inet_pton(family, text, $0.baseAddress) == 1 }
        return ok ? buffer : nil
    }

    var maxPrefix: Int { bytes.count * 8 }

    var isSingleHost: Bool { prefix == maxPrefix }

    var isDefaultRoute: Bool { prefix == 0 }

    var addressString: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBytes { raw in
            _ = inet_ntop(family == .v4 ? AF_INET : AF_INET6, raw.baseAddress, &buffer, socklen_t(buffer.count))
        }
        return String(cString: buffer)
    }

    /// The same range with host bits cleared, as routes expect.
    var network: IPAddressRange {
        var masked = bytes
        for i in 0..<masked.count {
            let bitsInByte = max(0, min(8, prefix - i * 8))
            masked[i] &= bitsInByte == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bitsInByte))
        }
        return IPAddressRange(family: family, bytes: masked, prefix: prefix)
    }

    /// Dotted-quad netmask (IPv4 only).
    var subnetMaskString: String {
        let mask: UInt32 = prefix == 0 ? 0 : ~UInt32(0) << (32 - UInt32(prefix))
        return "\(mask >> 24 & 0xFF).\(mask >> 16 & 0xFF).\(mask >> 8 & 0xFF).\(mask & 0xFF)"
    }

    var description: String {
        "\(addressString)/\(prefix)"
    }

    /// How tinc writes Subnets: the prefix is left out for single hosts.
    var tincSubnetString: String {
        isSingleHost ? addressString : description
    }
}
