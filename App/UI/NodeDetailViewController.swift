import UIKit

/// Details for one device: its addresses, how packets reach it, traffic,
/// and its host file.
final class NodeDetailViewController: StaticTableViewController {
    private let network: TincNetwork
    private let nodeName: String
    private var status: MeshStatus?
    private var timer: Timer?

    private var isMyself: Bool { nodeName == network.nodeName }

    init(network: TincNetwork, nodeName: String) {
        self.network = network
        self.nodeName = nodeName
        super.init()
        title = nodeName
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        if FileManager.default.fileExists(atPath: network.hostURL(nodeName).path) {
            navigationItem.rightBarButtonItem = UIBarButtonItem(systemItem: .action, primaryAction: UIAction { [weak self] action in
                guard let self else { return }
                self.share([self.network.hostURL(self.nodeName)], from: action.sender as? UIBarButtonItem)
            })
        }
        rebuild()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        timer?.invalidate()
        timer = nil
    }

    private func refresh() {
        guard TunnelController.shared.configuredNetworkName == network.name else {
            status = nil
            rebuild()
            return
        }
        TunnelController.shared.fetchStatus { [weak self] status in
            self?.status = status
            self?.rebuild()
        }
    }

    private func rebuild() {
        let node = status?.node(named: nodeName)
        let host = network.loadHost(nodeName)
        var result: [Section] = []

        // Addresses
        var addressRows: [Row] = []
        let subnets = node?.subnets ?? host?.values("Subnet") ?? []
        if isMyself {
            let interface = network.interfaceAddresses(network.loadSettings())
            addressRows += interface.map { Row("VPN address", .value($0.addressString, copyable: true)) }
        }
        addressRows += subnets.map { subnet in
            Row("Subnet", .value(subnet, copyable: true)) { [weak self] in
                self?.copyToPasteboard(IPAddressRange(subnet)?.addressString ?? subnet)
            }
        }
        if addressRows.isEmpty {
            addressRows.append(Row("Subnet", .value("None announced")))
        }
        result.append(Section("Addresses", rows: addressRows))

        // Connection
        if let node, let status {
            var rows: [Row] = [Row("Status", .value(Format.path(node)))]
            if !node.myself {
                if node.reachable, let address = node.address {
                    rows.append(Row("Endpoint", .value("\(address) port \(node.port ?? "?")", copyable: true)))
                }
                if let nexthop = node.nexthop, node.reachable, nexthop != node.name {
                    rows.append(Row("Next hop", .value(nexthop)))
                }
                rows.append(Row("Hops", .value(node.reachable ? String(node.distance) : "—")))
                if let rtt = node.rttMilliseconds {
                    rows.append(Row("UDP round trip", .value(String(format: "%.1f ms", rtt))))
                }
                if node.reachable {
                    rows.append(Row("Path MTU", .value(node.minmtu == node.maxmtu ? "\(node.mtu)" : "\(node.mtu) (probing)")))
                    rows.append(Row("Encryption", .value(node.validkey ? "SPTPS · ChaCha20-Poly1305" : "Key exchange pending")))
                }
                if node.compression > 0 {
                    rows.append(Row("Compression", .value("Level \(node.compression)")))
                }
                rows.append(Row(node.reachable ? "Online since" : "Offline since",
                                .value(Format.relative(epoch: node.lastStateChange, now: status.now))))
            } else if let port = status.port {
                rows.append(Row("Listening port", .value(port)))
            }
            result.append(Section("Connection", rows: rows))

            result.append(Section("Traffic", rows: [
                Row("Received", .value("\(Format.bytes(node.inBytes)) · \(node.inPackets) packets")),
                Row("Sent", .value("\(Format.bytes(node.outBytes)) · \(node.outPackets) packets")),
            ]))
        } else {
            result.append(Section("Connection",
                                  footer: "Connect to \(network.name) to see live status.",
                                  rows: [Row("Status", .value(TunnelController.shared.isActive ? "Not seen in the mesh" : "Disconnected"))]))
        }

        // Host file
        if let host {
            var rows: [Row] = []
            for address in host.values("Address") {
                rows.append(Row("Address", .value(address, copyable: true)))
            }
            if let port = host.value("Port") {
                rows.append(Row("Port", .value(port)))
            }
            if let key = host.value("Ed25519PublicKey") {
                rows.append(Row("Ed25519 public key", .subtitle(key, copyable: true)))
            }
            rows.append(Row("Edit Host File", .navigation(nil)) { [weak self] in self?.editHostFile() })
            result.append(Section("Host file", footer: hostFileFooter, rows: rows))
        }

        if !isMyself && host != nil {
            result.append(Section(rows: [
                Row("Remove Device", .button(destructive: true)) { [weak self] in self?.removeDevice() },
            ]))
        }

        sections = result
    }

    private var hostFileFooter: String {
        isMyself
            ? "Share this file with other nodes so they can verify and reach this device."
            : "This file holds \(nodeName)'s public key. Without it, this device will only learn about \(nodeName) through the mesh."
    }

    private func editHostFile() {
        let editor = TextEditorViewController(title: nodeName, url: network.hostURL(nodeName)) { [network] in
            TunnelController.shared.reloadIfActive(network)
        }
        navigationController?.pushViewController(editor, animated: true)
    }

    private func removeDevice() {
        confirm(title: "Remove \(nodeName)?",
                message: "This deletes its host file. If StrictSubnets or TunnelServer is not set, it may still be reachable through other nodes.",
                actionTitle: "Remove") { [weak self] in
            guard let self else { return }
            do {
                try NetworkStore.shared.removeHost(name: self.nodeName, from: self.network)
                TunnelController.shared.reloadIfActive(self.network)
                NotificationCenter.default.post(name: .networksDidChange, object: nil)
                self.navigationController?.popViewController(animated: true)
            } catch {
                self.showError(error)
            }
        }
    }
}
