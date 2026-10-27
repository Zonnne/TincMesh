import CTinc
import Foundation

/// Swift wrappers around the C API in TincCore/ios/tinc_ios.h.
enum TincCore {
    static var version: String {
        String(cString: tinc_ios_version())
    }

    struct JoinResult: Decodable {
        let name: String
        let netname: String
        let ifconfig: [String]
        let routes: [String]
    }

    /// Generates an Ed25519 key pair, writing the private key; returns the public key.
    static func generateKey(privateKeyURL: URL) throws -> String {
        guard let pub = tinc_ios_generate_key(privateKeyURL.path) else {
            throw TincMeshError("Could not generate an Ed25519 key.")
        }
        defer { free(pub) }
        return String(cString: pub)
    }

    static func publicKey(privateKeyURL: URL) -> String? {
        guard let pub = tinc_ios_public_key_from_private(privateKeyURL.path) else { return nil }
        defer { free(pub) }
        return String(cString: pub)
    }

    /// Accepts an invitation into `directory`. Blocks on network I/O.
    static func join(directory: URL, invitation: String, timeout: Int32 = 15) throws -> JoinResult {
        var error = [CChar](repeating: 0, count: 512)
        guard let json = tinc_ios_join(directory.path, invitation, timeout, &error, error.count) else {
            let message = String(cString: error)
            throw TincMeshError(message.isEmpty ? "Could not accept the invitation." : message)
        }
        defer { free(json) }
        return try JSONDecoder().decode(JoinResult.self, from: Data(String(cString: json).utf8))
    }

    /// Creates an invitation for a new node; returns its URL.
    static func invite(directory: URL, netname: String?, invitee: String, address: String, extraLines: String?) throws -> String {
        var error = [CChar](repeating: 0, count: 512)
        guard let url = tinc_ios_invite(directory.path, netname, invitee, address, extraLines, &error, error.count) else {
            let message = String(cString: error)
            throw TincMeshError(message.isEmpty ? "Could not create the invitation." : message)
        }
        defer { free(url) }
        return String(cString: url)
    }
}
