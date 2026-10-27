import UIKit

/// Starts a new network with this device as its first node, like `tinc init`.
/// Other nodes are added by exchanging host files or with invitations.
final class CreateNetworkViewController: FormViewController {
    init() {
        let suggestedSubnet = "10.\(Int.random(in: 1...254)).\(Int.random(in: 0...255))"
        super.init(
            title: "New Network",
            fields: [
                Field(key: "netname", label: "Network name", placeholder: "home", text: "",
                      footer: "Used as the netname, like /etc/tinc/NETNAME on other platforms."),
                Field(key: "node", label: "This device's name", placeholder: "phone",
                      text: CreateNetworkViewController.suggestedNodeName(),
                      footer: "Letters, digits and underscores only."),
                Field(key: "address", label: "VPN address", placeholder: "10.0.0.1/24",
                      text: "\(suggestedSubnet).1/24", keyboard: .numbersAndPunctuation,
                      footer: "This device's address and the size of the VPN network.", monospaced: true),
                Field(key: "public", label: "Public address (optional)", placeholder: "vpn.example.com",
                      keyboard: .URL,
                      footer: "Only if other nodes can reach this device directly, for example on a LAN."),
                Field(key: "port", label: "Port (optional)", placeholder: "655",
                      keyboard: .numberPad, footer: "Leave empty to use a random port."),
                Field(key: "connect", label: "Connect to (optional)", placeholder: "server1, server2",
                      footer: "Nodes to connect to. Add their host files afterwards in Settings."),
            ],
            submitTitle: "Create",
            submit: CreateNetworkViewController.create)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    private static func suggestedNodeName() -> String {
        let cleaned = UIDevice.current.name.unicodeScalars.map { scalar -> Character in
            scalar.isASCII && CharacterSet.alphanumerics.contains(scalar) ? Character(scalar) : "_"
        }
        let name = String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "_"))
        return name.isEmpty ? "phone" : name
    }

    private static func create(_ values: [String: String]) async throws {
        guard let address = IPAddressRange(values["address"] ?? "") else {
            throw TincMeshError("Enter the VPN address in CIDR form, e.g. 10.0.0.1/24.")
        }
        var port: Int?
        if let portText = values["port"], !portText.isEmpty {
            guard let value = Int(portText), (1...65535).contains(value) else {
                throw TincMeshError("The port must be between 1 and 65535.")
            }
            port = value
        }
        let connectTo = (values["connect"] ?? "")
            .split(whereSeparator: { $0 == "," || $0 == " " })
            .map(String.init)
        if let invalid = connectTo.first(where: { !TincConfigFile.isValidNodeName($0) }) {
            throw TincMeshError("“\(invalid)” is not a valid node name.")
        }

        let spec = NetworkStore.NewNetwork(
            netname: values["netname"] ?? "",
            nodeName: values["node"] ?? "",
            address: address,
            publicAddress: values["public"],
            port: port,
            connectTo: connectTo)
        let network = try await Task.detached(priority: .userInitiated) {
            try NetworkStore.shared.create(spec)
        }.value

        await MainActor.run {
            NetworkStore.shared.activeNetwork = network
            NotificationCenter.default.post(name: .networksDidChange, object: nil)
            let window = UIApplication.shared.connectedScenes
                .compactMap { ($0 as? UIWindowScene)?.keyWindow }.first
            window?.rootViewController?.dismiss(animated: true)
        }
    }
}
