import UIKit
import UniformTypeIdentifiers

/// Settings for one network: this device's identity, the iOS interface
/// configuration (what tinc-up does elsewhere), peers, and raw config access.
final class NetworkSettingsViewController: StaticTableViewController, UIDocumentPickerDelegate {
    private var network: TincNetwork

    init(network: TincNetwork) {
        self.network = network
        super.init()
        title = "Settings"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        NotificationCenter.default.addObserver(forName: .tunnelStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.rebuild()
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        rebuild()
    }

    private var settings: TunnelSettings {
        network.loadSettings()
    }

    private func updateSettings(reconnect: Bool = true, _ change: (inout TunnelSettings) -> Void) {
        var updated = settings
        change(&updated)
        do {
            try network.saveSettings(updated)
            if reconnect {
                TunnelController.shared.reconnectIfActive(network)
            }
        } catch {
            showError(error)
        }
        rebuild()
    }

    // MARK: - Sections

    private func rebuild() {
        let settings = self.settings
        let config = network.loadConfig()
        let me = network.nodeName ?? "?"
        let tunnel = TunnelController.shared
        let interface = network.interfaceAddresses(settings)

        var result: [Section] = []

        result.append(Section("This device", rows: [
            Row("Name", .value(me)),
            Row("Public key", .subtitle(TincCore.publicKey(privateKeyURL: network.privateKeyURL) ?? "Missing", copyable: true)),
            Row("Share Host File", .button()) { [weak self] in self?.shareOwnHostFile() },
        ]))

        result.append(Section(
            "VPN interface",
            footer: "These replace the tinc-up script, which iOS cannot run. Without explicit addresses, this device's single-host Subnets are used.",
            rows: [
                Row("Addresses", .navigation(settings.addresses.isEmpty ? interface.map(\.description).joined(separator: ", ") : summary(settings.addresses))) { [weak self] in
                    self?.editList(title: "Addresses", values: settings.addresses, placeholder: "10.0.0.5/24", validate: Self.validCIDR) { list in
                        self?.updateSettings { $0.addresses = list }
                    }
                },
                Row("Routes", .navigation(summary(settings.routes))) { [weak self] in
                    self?.editList(title: "Routes", values: settings.routes, placeholder: "192.168.10.0/24", validate: Self.validCIDR) { list in
                        self?.updateSettings { $0.routes = list }
                    }
                },
                Row("Route Peer Subnets", .toggle(settings.routePeerSubnets, { [weak self] on in
                    self?.updateSettings { $0.routePeerSubnets = on }
                })),
                Row("Use Exit Node", .toggle(settings.useExitNode, { [weak self] on in
                    self?.updateSettings { $0.useExitNode = on }
                })),
                Row("MTU", .navigation(String(settings.mtu))) { [weak self] in self?.editMTU() },
            ]))

        result.append(Section(
            "Routing",
            footer: "Send chosen sites through chosen nodes, for example streaming through one exit node and work traffic through another.",
            rows: [
                Row("Rules", .navigation(settings.rulesEnabled ? "On" : "Off"), image: UIImage(systemName: "arrow.triangle.branch")) { [weak self] in
                    guard let self else { return }
                    self.navigationController?.pushViewController(RulesViewController(network: self.network), animated: true)
                },
            ]))

        result.append(Section(
            "DNS",
            footer: "With search domains set, only those names are resolved by these servers unless an exit node is used.",
            rows: [
                Row("Servers", .navigation(summary(settings.dnsServers))) { [weak self] in
                    self?.editList(title: "DNS Servers", values: settings.dnsServers, placeholder: "10.0.0.1", validate: Self.validAddress) { list in
                        self?.updateSettings { $0.dnsServers = list }
                    }
                },
                Row("Search Domains", .navigation(summary(settings.searchDomains))) { [weak self] in
                    self?.editList(title: "Search Domains", values: settings.searchDomains, placeholder: "mesh.example", validate: { !$0.contains(" ") }) { list in
                        self?.updateSettings { $0.searchDomains = list }
                    }
                },
            ]))

        result.append(Section(
            "Connection",
            footer: "Always On uses VPN On Demand to reconnect automatically whenever a network is available.",
            rows: [
                Row("Always On", .toggle(tunnel.isOnDemandEnabled && tunnel.configuredNetworkName == network.name, { [weak self] on in
                    self?.setAlwaysOn(on)
                })),
                Row("Connect To", .navigation(summary(config?.values("ConnectTo") ?? []))) { [weak self] in
                    self?.editConnectTo()
                },
                Row("Log Level", .navigation(Self.logLevelNames[min(max(settings.logLevel, 0), Self.logLevelNames.count - 1)])) { [weak self] in
                    self?.chooseLogLevel()
                },
                Row("Log", .navigation(nil)) { [weak self] in
                    self?.navigationController?.pushViewController(LogViewController(), animated: true)
                },
            ]))

        result.append(Section("Devices", rows: [
            Row("Invite a Device…", .button(), image: UIImage(systemName: "person.badge.plus")) { [weak self] in
                guard let self else { return }
                self.present(UINavigationController(rootViewController: InviteViewController(network: self.network)), animated: true)
            },
            Row("Paste a Host File…", .button(), image: UIImage(systemName: "doc.on.clipboard")) { [weak self] in
                self?.pasteHostFile()
            },
            Row("Import Host Files…", .button(), image: UIImage(systemName: "folder")) { [weak self] in
                self?.importHostFiles()
            },
        ]))

        result.append(Section("Configuration files", footer: "Changes to tinc.conf and host files are applied with a reload while connected.", rows: [
            Row("tinc.conf", .navigation(nil)) { [weak self] in
                guard let self else { return }
                self.openEditor(title: "tinc.conf", url: self.network.tincConfURL)
            },
            Row("All Files", .navigation(nil)) { [weak self] in
                guard let self else { return }
                self.navigationController?.pushViewController(FilesViewController(network: self.network), animated: true)
            },
        ]))

        result.append(Section(footer: "tinc \(TincCore.version), SPTPS protocol 17.7 (Ed25519, X25519, ChaCha20-Poly1305).", rows: [
            Row("Rename Network", .button()) { [weak self] in self?.renameNetwork() },
            Row("Delete Network", .button(destructive: true)) { [weak self] in self?.deleteNetwork() },
        ]))

        sections = result
    }

    private func summary(_ values: [String]) -> String {
        switch values.count {
        case 0: return "None"
        case 1: return values[0]
        default: return "\(values[0]) +\(values.count - 1)"
        }
    }

    private static let logLevelNames = ["0 · Basic", "1 · Connections", "2 · Errors", "3 · Status", "4 · Protocol", "5 · Meta"]

    private static func validCIDR(_ text: String) -> Bool {
        IPAddressRange(text) != nil
    }

    private static func validAddress(_ text: String) -> Bool {
        IPAddressRange(text)?.isSingleHost == true && !text.contains("/")
    }

    // MARK: - Actions

    private func editList(title: String, values: [String], placeholder: String,
                          validate: @escaping (String) -> Bool, onChange: @escaping ([String]) -> Void) {
        let editor = ListEditorViewController(title: title, values: values, placeholder: placeholder, validate: validate, onChange: onChange)
        navigationController?.pushViewController(editor, animated: true)
    }

    private func editConnectTo() {
        let values = network.loadConfig()?.values("ConnectTo") ?? []
        editList(title: "Connect To", values: values, placeholder: "server1", validate: TincConfigFile.isValidNodeName) { [weak self] list in
            guard let self, var config = self.network.loadConfig() else { return }
            config.setAll("ConnectTo", list)
            do {
                try self.network.saveConfig(config)
                TunnelController.shared.reloadIfActive(self.network)
            } catch {
                self.showError(error)
            }
        }
    }

    private func editMTU() {
        let alert = UIAlertController(title: "MTU", message: "Between 576 and 1500. tinc discovers the path MTU to each peer separately.", preferredStyle: .alert)
        alert.addTextField { field in
            field.text = String(self.settings.mtu)
            field.keyboardType = .numberPad
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Save", style: .default) { [weak self, weak alert] _ in
            guard let text = alert?.textFields?.first?.text, let mtu = Int(text), (576...1500).contains(mtu) else {
                self?.showAlert(title: "Invalid MTU", message: "Enter a value between 576 and 1500.")
                return
            }
            self?.updateSettings { $0.mtu = mtu }
        })
        present(alert, animated: true)
    }

    private func chooseLogLevel() {
        let sheet = UIAlertController(title: "Log Level", message: "Higher levels are useful for troubleshooting but log a lot.", preferredStyle: .actionSheet)
        for (level, name) in Self.logLevelNames.enumerated() {
            sheet.addAction(UIAlertAction(title: name, style: .default) { [weak self] _ in
                self?.updateSettings { $0.logLevel = level }
            })
        }
        sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        sheet.popoverPresentationController?.sourceView = view
        present(sheet, animated: true)
    }

    private func setAlwaysOn(_ enabled: Bool) {
        let tunnel = TunnelController.shared
        let apply = {
            tunnel.setOnDemand(enabled) { [weak self] error in
                if let error { self?.showError(error) }
                self?.rebuild()
            }
        }
        if enabled && tunnel.configuredNetworkName != network.name {
            // On Demand starts whichever network the VPN configuration points at.
            tunnel.connect(to: network) { [weak self] error in
                if let error {
                    self?.showError(error, title: "Could not connect")
                    self?.rebuild()
                } else {
                    apply()
                }
            }
        } else {
            apply()
        }
    }

    private func openEditor(title: String, url: URL) {
        let editor = TextEditorViewController(title: title, url: url) { [network] in
            TunnelController.shared.reloadIfActive(network)
            NotificationCenter.default.post(name: .networksDidChange, object: nil)
        }
        navigationController?.pushViewController(editor, animated: true)
    }

    private func shareOwnHostFile() {
        guard let me = network.nodeName else { return }
        share([network.hostURL(me)], sourceView: tableView)
    }

    private func pasteHostFile() {
        let alert = UIAlertController(title: "Add Host File", message: "Name of the node whose host file is on the clipboard.", preferredStyle: .alert)
        alert.addTextField { field in
            field.placeholder = "node name"
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Add", style: .default) { [weak self, weak alert] _ in
            guard let self else { return }
            let name = alert?.textFields?.first?.text?.trimmingCharacters(in: .whitespaces) ?? ""
            do {
                guard let contents = UIPasteboard.general.string else {
                    throw TincMeshError("The clipboard does not contain text.")
                }
                try NetworkStore.shared.importHost(name: name, contents: contents, into: self.network)
                self.hostsChanged(added: [name])
            } catch {
                self.showError(error, title: "Could not add host file")
            }
        })
        present(alert, animated: true)
    }

    private func importHostFiles() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data, .text, .item], asCopy: true)
        picker.allowsMultipleSelection = true
        picker.delegate = self
        present(picker, animated: true)
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        var added: [String] = []
        var failures: [String] = []
        for url in urls {
            // tinc host files are named after their node.
            let name = url.lastPathComponent
            do {
                let contents = try String(contentsOf: url, encoding: .utf8)
                try NetworkStore.shared.importHost(name: name, contents: contents, into: network)
                added.append(name)
            } catch {
                failures.append("\(name): \(error.localizedDescription)")
            }
        }
        hostsChanged(added: added)
        if !failures.isEmpty {
            showAlert(title: "Some files were not imported", message: failures.joined(separator: "\n"))
        }
    }

    private func hostsChanged(added: [String]) {
        guard !added.isEmpty else { return }
        TunnelController.shared.reloadIfActive(network)
        NotificationCenter.default.post(name: .networksDidChange, object: nil)
        Toast.show("Added \(added.joined(separator: ", "))", in: view.window ?? view)
        rebuild()
    }

    private func renameNetwork() {
        let alert = UIAlertController(title: "Rename Network", message: nil, preferredStyle: .alert)
        alert.addTextField { [network] field in
            field.text = network.name
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Rename", style: .default) { [weak self, weak alert] _ in
            guard let self, let name = alert?.textFields?.first?.text, name != self.network.name else { return }
            let wasActive = TunnelController.shared.configuredNetworkName == self.network.name && TunnelController.shared.isActive
            do {
                if wasActive { TunnelController.shared.disconnect() }
                self.network = try NetworkStore.shared.rename(self.network, to: name)
                NotificationCenter.default.post(name: .networksDidChange, object: nil)
                if wasActive {
                    TunnelController.shared.connect(to: self.network) { _ in }
                }
                self.rebuild()
            } catch {
                self.showError(error)
            }
        })
        present(alert, animated: true)
    }

    private func deleteNetwork() {
        confirm(title: "Delete \(network.name)?",
                message: "This removes its configuration and this device's private key. This cannot be undone.",
                actionTitle: "Delete Network") { [weak self] in
            guard let self else { return }
            let tunnel = TunnelController.shared
            let finish = {
                do {
                    try NetworkStore.shared.delete(self.network)
                    NotificationCenter.default.post(name: .networksDidChange, object: nil)
                    self.navigationController?.popToRootViewController(animated: true)
                } catch {
                    self.showError(error)
                }
            }
            if tunnel.configuredNetworkName == self.network.name {
                tunnel.disconnect()
                tunnel.removeConfiguration(completion: finish)
            } else {
                finish()
            }
        }
    }
}
