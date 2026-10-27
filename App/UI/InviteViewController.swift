import UIKit

/// Creates an invitation for a new device (like `tinc invite NAME`), optionally
/// assigning it a VPN address. This device must be reachable by the invitee
/// and connected while the invitation is used, because tinc serves it.
final class InviteViewController: FormViewController {
    private let network: TincNetwork

    init(network: TincNetwork) {
        self.network = network
        let host = network.nodeName.flatMap(network.loadHost)
        var reachableAt = host?.value("Address") ?? ""
        if !reachableAt.isEmpty, let port = host?.value("Port"), port != "655" {
            reachableAt += ":\(port)"
        }
        super.init(
            title: "Invite Device",
            fields: [
                Field(key: "name", label: "New device's name", placeholder: "laptop",
                      footer: "Letters, digits and underscores only."),
                Field(key: "address", label: "VPN address (optional)", placeholder: "10.0.0.7/24",
                      text: InviteViewController.suggestAddress(in: network), keyboard: .numbersAndPunctuation,
                      footer: "Assigned to the new device through Ifconfig and Subnet lines in the invitation.",
                      monospaced: true),
                Field(key: "reach", label: "This device's reachable address", placeholder: "vpn.example.com:655",
                      text: reachableAt, keyboard: .URL,
                      footer: "How the new device connects to this one to fetch the invitation. If this device is not reachable, create the invitation on a server instead."),
            ],
            submitTitle: "Create",
            submit: { _ in })
        submitHandler = { [weak self] values in
            try await self?.createInvitation(values)
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    /// The next address after the highest one in use, within this device's network.
    private static func suggestAddress(in network: TincNetwork) -> String {
        let settings = network.loadSettings()
        guard let mine = network.interfaceAddresses(settings).first(where: { $0.family == .v4 && !$0.isSingleHost })
                ?? settings.routes.compactMap(IPAddressRange.init).first(where: { $0.family == .v4 }) else {
            return ""
        }
        var used = Set<UInt32>()
        for host in network.hostNames() {
            for subnet in network.subnets(of: host) where subnet.family == .v4 {
                used.insert(subnet.bytes.reduce(0) { $0 << 8 | UInt32($1) })
            }
        }
        used.insert(mine.bytes.reduce(0) { $0 << 8 | UInt32($1) })
        let base = mine.network.bytes.reduce(0) { $0 << 8 | UInt32($1) }
        let size = UInt32(1) << UInt32(32 - mine.prefix)
        guard size > 2, let next = (1..<size - 1).lazy.map({ base + $0 }).first(where: { !used.contains($0) }) else { return "" }
        return "\(next >> 24 & 0xFF).\(next >> 16 & 0xFF).\(next >> 8 & 0xFF).\(next & 0xFF)/\(mine.prefix)"
    }

    @MainActor
    private func createInvitation(_ values: [String: String]) async throws {
        let name = values["name"] ?? ""
        let addressText = values["address"] ?? ""
        guard TincConfigFile.isValidNodeName(name) else {
            throw TincMeshError("Enter a name using only letters, digits and underscores.")
        }
        var vpnAddress: IPAddressRange?
        if !addressText.isEmpty {
            guard let parsed = IPAddressRange(addressText) else {
                throw TincMeshError("Enter the VPN address in CIDR form, e.g. 10.0.0.7/24.")
            }
            vpnAddress = parsed
        }
        let url = try NetworkStore.shared.invite(network: network, invitee: name, address: values["reach"] ?? "", vpnAddress: vpnAddress)
        // A running tinc must load the invitation key before it can serve the invitation.
        TunnelController.shared.reloadIfActive(network)
        navigationController?.pushViewController(InvitationResultViewController(url: url, invitee: name), animated: true)
    }
}

/// Shows an invitation as a QR code and text.
final class InvitationResultViewController: UIViewController {
    private let url: String
    private let invitee: String

    init(url: String, invitee: String) {
        self.url = url
        self.invitee = invitee
        super.init(nibName: nil, bundle: nil)
        title = "Invitation"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemGroupedBackground
        navigationItem.hidesBackButton = true
        navigationItem.rightBarButtonItem = UIBarButtonItem(systemItem: .done, primaryAction: UIAction { [weak self] _ in
            self?.dismiss(animated: true)
        })

        let qr = UIImageView(image: QRCode.image(for: url, size: 260))
        qr.contentMode = .scaleAspectFit
        qr.layer.magnificationFilter = .nearest
        qr.backgroundColor = .white
        qr.layer.cornerRadius = 12
        qr.clipsToBounds = true

        let heading = UILabel()
        heading.text = "Scan with TincMesh on \(invitee), or run:"
        heading.font = .preferredFont(forTextStyle: .headline)
        heading.numberOfLines = 0
        heading.textAlignment = .center

        let command = UILabel()
        command.text = "tinc join \(url)"
        command.font = .monospaced(.footnote)
        command.numberOfLines = 0
        command.textAlignment = .center
        command.textColor = .secondaryLabel

        let note = UILabel()
        note.text = "The invitation works once and expires after a week. Keep this device connected until it has been used."
        note.font = .preferredFont(forTextStyle: .footnote)
        note.textColor = .secondaryLabel
        note.numberOfLines = 0
        note.textAlignment = .center

        var copyConfig = UIButton.Configuration.gray()
        copyConfig.title = "Copy"
        copyConfig.image = UIImage(systemName: "doc.on.doc")
        copyConfig.imagePadding = 6
        let copy = UIButton(configuration: copyConfig, primaryAction: UIAction { [weak self] _ in
            guard let self else { return }
            self.copyToPasteboard(self.url, label: "Invitation copied")
        })

        var shareConfig = UIButton.Configuration.filled()
        shareConfig.title = "Share"
        shareConfig.image = UIImage(systemName: "square.and.arrow.up")
        shareConfig.imagePadding = 6
        let shareButton = UIButton(configuration: shareConfig)
        shareButton.addAction(UIAction { [weak self, weak shareButton] _ in
            guard let self else { return }
            self.share([self.url], sourceView: shareButton)
        }, for: .primaryActionTriggered)

        let buttons = UIStackView(arrangedSubviews: [copy, shareButton])
        buttons.spacing = 12
        buttons.distribution = .fillEqually

        let stack = UIStackView(arrangedSubviews: [qr, heading, command, buttons, note])
        stack.axis = .vertical
        stack.spacing = 16
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false

        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.addSubview(stack)
        view.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: view.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            scroll.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24),
            stack.leadingAnchor.constraint(equalTo: view.readableContentGuide.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: view.readableContentGuide.trailingAnchor),
            qr.widthAnchor.constraint(equalToConstant: 260),
            qr.heightAnchor.constraint(equalToConstant: 260),
            buttons.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }
}
