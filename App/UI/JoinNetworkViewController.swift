import UIKit

/// Joins a network with an invitation URL from `tinc invite`
/// (host[:port]/<48 characters>), typed, pasted or scanned as a QR code.
final class JoinNetworkViewController: FormViewController {
    init(invitation: String = "") {
        super.init(
            title: "Join Network",
            fields: [
                Field(key: "url", label: "Invitation", placeholder: "vpn.example.com/AbCd…",
                      text: invitation, keyboard: .URL,
                      footer: "Create one on an existing node with “tinc -n NETNAME invite NEWNODE”.",
                      monospaced: true),
                Field(key: "netname", label: "Network name (optional)", placeholder: "Taken from the invitation",
                      footer: "A local name for this network."),
            ],
            submitTitle: "Join",
            submit: JoinNetworkViewController.join)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        let paste = UIBarButtonItem(title: "Paste", image: UIImage(systemName: "doc.on.clipboard"), primaryAction: UIAction { [weak self] _ in
            if let text = UIPasteboard.general.string {
                self?.setValue(text.trimmingCharacters(in: .whitespacesAndNewlines), for: "url")
            }
        })
        let scan = UIBarButtonItem(title: "Scan", image: UIImage(systemName: "qrcode.viewfinder"), primaryAction: UIAction { [weak self] _ in
            self?.scan()
        })
        toolbarItems = [paste, UIBarButtonItem(systemItem: .flexibleSpace), scan]
        navigationController?.isToolbarHidden = false
    }

    private func scan() {
        let scanner = QRScannerViewController { [weak self] code in
            self?.setValue(code, for: "url")
        }
        present(UINavigationController(rootViewController: scanner), animated: true)
    }

    private static func join(_ values: [String: String]) async throws {
        let url = values["url"] ?? ""
        guard !url.isEmpty else { throw TincMeshError("Enter or scan an invitation.") }
        let netname = values["netname"].flatMap { $0.isEmpty ? nil : $0 }

        let network = try await Task.detached(priority: .userInitiated) {
            try NetworkStore.shared.join(invitation: url, netname: netname)
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
