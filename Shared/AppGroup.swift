import Foundation

/// The App Group container shared by the app and the packet tunnel extension.
///
/// Layout:
///
///     <container>/networks/<netname>/tinc.conf
///                                   /hosts/<node>
///                                   /ed25519_key.priv
///                                   /ios.json          (TunnelSettings)
///     <container>/tinc.log, tinc.log.1                  (written by the extension)
enum AppGroup {
    /// Set per build in Config/Shared.xcconfig and exposed through Info.plist.
    static let identifier: String =
        Bundle.main.object(forInfoDictionaryKey: "TincMeshAppGroup") as? String ?? "group.com.example.tincmesh"

    static var containerURL: URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) {
            return url
        }
        // Only reached when the App Group entitlement is missing (misconfigured signing).
        // The app keeps working, but the extension will not see its networks.
        NSLog("TincMesh: App Group %@ unavailable, falling back to Application Support", identifier)
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    static var networksURL: URL {
        containerURL.appendingPathComponent("networks", isDirectory: true)
    }

    static var logURL: URL {
        containerURL.appendingPathComponent("tinc.log")
    }

    static var rotatedLogURL: URL {
        containerURL.appendingPathComponent("tinc.log.1")
    }

    static var defaults: UserDefaults {
        UserDefaults(suiteName: identifier) ?? .standard
    }
}

struct TincMeshError: LocalizedError {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var errorDescription: String? { message }
}
