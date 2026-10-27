import UIKit

/// All configured networks. One is active at a time (iOS runs one VPN).
final class NetworksViewController: UITableViewController {
    private var networks: [TincNetwork] = []

    init() {
        super.init(style: .insetGrouped)
        title = "Networks"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        navigationItem.rightBarButtonItem = UIBarButtonItem(systemItem: .add, menu: UIMenu(children: [
            UIAction(title: "Join with Invitation…", image: UIImage(systemName: "qrcode.viewfinder")) { [weak self] _ in
                self?.present(UINavigationController(rootViewController: JoinNetworkViewController()), animated: true)
            },
            UIAction(title: "Create Network…", image: UIImage(systemName: "plus.circle")) { [weak self] _ in
                self?.present(UINavigationController(rootViewController: CreateNetworkViewController()), animated: true)
            },
        ]))
        NotificationCenter.default.addObserver(forName: .networksDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.reload()
        }
        NotificationCenter.default.addObserver(forName: .tunnelStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.reload()
        }
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reload()
    }

    private func reload() {
        networks = NetworkStore.shared.networks()
        tableView.reloadData()
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        networks.count
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        networks.isEmpty
            ? "No networks yet. Tap + to join one with an invitation or create a new one."
            : "Each network is a tinc configuration directory with its own keys. Selecting one switches the VPN to it."
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let network = networks[indexPath.row]
        let tunnel = TunnelController.shared
        let isActive = NetworkStore.shared.activeNetwork == network
        let cell = UITableViewCell(style: .default, reuseIdentifier: nil)
        var content = UIListContentConfiguration.subtitleCell()
        content.text = network.name
        var detail = network.nodeName.map { "This device: \($0)" } ?? "No Name in tinc.conf"
        if tunnel.configuredNetworkName == network.name && tunnel.status != .disconnected && tunnel.status != .invalid {
            detail += " · \(tunnel.status.displayName)"
        }
        if let problem = network.validate() {
            detail += "\n⚠︎ \(problem)"
        }
        content.secondaryText = detail
        content.secondaryTextProperties.color = .secondaryLabel
        content.image = UIImage(systemName: "point.3.connected.trianglepath.dotted")
        cell.contentConfiguration = content
        cell.accessoryType = isActive ? .checkmark : .none
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let network = networks[indexPath.row]
        let tunnel = TunnelController.shared
        let wasActive = tunnel.isActive
        NetworkStore.shared.activeNetwork = network
        NotificationCenter.default.post(name: .networksDidChange, object: nil)
        if wasActive && tunnel.configuredNetworkName != network.name {
            tunnel.connect(to: network) { [weak self] error in
                if let error { self?.showError(error, title: "Could not connect") }
            }
        }
        navigationController?.popViewController(animated: true)
    }

    override func tableView(_ tableView: UITableView,
                            trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let network = networks[indexPath.row]
        let settings = UIContextualAction(style: .normal, title: "Settings") { [weak self] _, _, done in
            self?.navigationController?.pushViewController(NetworkSettingsViewController(network: network), animated: true)
            done(true)
        }
        settings.image = UIImage(systemName: "gearshape")
        return UISwipeActionsConfiguration(actions: [settings])
    }
}
