import UIKit

/// Lists a network's configuration files for direct editing, as you would
/// in /etc/tinc/NETNAME on a desktop. The private key is never shown.
final class FilesViewController: StaticTableViewController {
    private let network: TincNetwork

    init(network: TincNetwork) {
        self.network = network
        super.init()
        title = "Files"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        rebuild()
    }

    private func rebuild() {
        let fileImage = UIImage(systemName: "doc.text")
        var top: [Row] = [
            Row("tinc.conf", .navigation(nil), image: fileImage) { [weak self] in
                guard let self else { return }
                self.edit("tinc.conf", self.network.tincConfURL)
            },
            Row(TunnelSettings.fileName, .navigation("iOS settings"), image: fileImage) { [weak self] in
                guard let self else { return }
                self.edit(TunnelSettings.fileName, self.network.settingsURL)
            },
        ]
        let invitationData = network.directory.appendingPathComponent("invitation-data")
        if FileManager.default.fileExists(atPath: invitationData.path) {
            top.append(Row("invitation-data", .navigation(nil), image: fileImage) { [weak self] in
                self?.edit("invitation-data", invitationData)
            })
        }

        let me = network.nodeName
        let hosts = network.hostNames().map { name in
            Row(name, .navigation(name == me ? "this device" : nil), image: UIImage(systemName: "server.rack")) { [weak self] in
                guard let self else { return }
                self.edit(name, self.network.hostURL(name))
            }
        }

        sections = [
            Section(network.name, footer: "ed25519_key.priv is kept private and not shown.", rows: top),
            Section("hosts", rows: hosts),
        ]
    }

    private func edit(_ title: String, _ url: URL) {
        let editor = TextEditorViewController(title: title, url: url) { [network] in
            TunnelController.shared.reloadIfActive(network)
            NotificationCenter.default.post(name: .networksDidChange, object: nil)
        }
        navigationController?.pushViewController(editor, animated: true)
    }
}
