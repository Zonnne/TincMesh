import NetworkExtension
import UIKit

extension Notification.Name {
    /// Posted when networks are created, joined, renamed, deleted or edited.
    static let networksDidChange = Notification.Name("TincMeshNetworksDidChange")
}

/// The main screen: the active network's devices with a connect toggle,
/// similar to Tailscale's machine list.
final class MeshViewController: UITableViewController, UISearchResultsUpdating {
    private struct Device {
        let name: String
        let node: MeshStatus.Node?
        let subnets: [String]
        let isMyself: Bool
    }

    private struct DeviceSection {
        let title: String
        let devices: [Device]
    }

    private var network: TincNetwork?
    private var meshStatus: MeshStatus?
    private var deviceSections: [DeviceSection] = []
    private var searchText = ""
    private var refreshTimer: Timer?

    private let connectSwitch = UISwitch()
    private let header = StatusHeaderView()
    private lazy var welcomeView = WelcomeView(
        onJoin: { [weak self] in self?.presentJoin() },
        onCreate: { [weak self] in self?.presentCreate() })

    private var tunnel: TunnelController { .shared }

    private var isConnectedToThisNetwork: Bool {
        tunnel.status == .connected && tunnel.configuredNetworkName == network?.name
    }

    init() {
        super.init(style: .insetGrouped)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationController?.navigationBar.prefersLargeTitles = true
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "device")

        let search = UISearchController(searchResultsController: nil)
        search.searchResultsUpdater = self
        search.obscuresBackgroundDuringPresentation = false
        search.searchBar.placeholder = "Search devices and addresses"
        navigationItem.searchController = search

        refreshControl = UIRefreshControl()
        refreshControl?.addAction(UIAction { [weak self] _ in self?.manualRefresh() }, for: .valueChanged)

        connectSwitch.addAction(UIAction { [weak self] _ in self?.connectSwitchChanged() }, for: .valueChanged)

        let center = NotificationCenter.default
        center.addObserver(forName: .tunnelStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.tunnelStatusChanged()
        }
        center.addObserver(forName: .networksDidChange, object: nil, queue: .main) { [weak self] _ in
            self?.reloadNetwork()
        }
        center.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: .main) { [weak self] _ in
            self?.tunnel.load { self?.reloadNetwork() }
        }

        tunnel.load { [weak self] in self?.reloadNetwork() }
        reloadNetwork()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reloadNetwork()
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            self?.fetchStatus()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        refreshTimer?.invalidate()
        refreshTimer = nil
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        sizeHeaderToFit()
    }

    // MARK: - State

    private func reloadNetwork() {
        network = NetworkStore.shared.activeNetwork
        if tunnel.configuredNetworkName != network?.name {
            meshStatus = nil
        }
        updateNavigationItems()
        rebuild()
        fetchStatus()
    }

    private func tunnelStatusChanged() {
        if !isConnectedToThisNetwork {
            meshStatus = nil
        }
        updateNavigationItems()
        rebuild()
        fetchStatus()
    }

    private func fetchStatus() {
        guard isConnectedToThisNetwork else { return }
        tunnel.fetchStatus { [weak self] status in
            guard let self, self.isConnectedToThisNetwork else { return }
            self.meshStatus = status
            self.rebuild()
        }
    }

    private func manualRefresh() {
        tunnel.load { [weak self] in
            self?.reloadNetwork()
            self?.refreshControl?.endRefreshing()
        }
    }

    private func rebuild() {
        guard let network else {
            deviceSections = []
            tableView.backgroundView = welcomeView
            tableView.tableHeaderView = nil
            tableView.reloadData()
            return
        }
        tableView.backgroundView = nil
        tableView.tableHeaderView = header

        let myName = network.nodeName
        let status = isConnectedToThisNetwork ? meshStatus : nil
        var names = Set(network.hostNames())
        status?.nodes.forEach { names.insert($0.name) }
        if let myName { names.remove(myName) }

        func device(_ name: String) -> Device {
            let node = status?.node(named: name)
            let subnets = node?.subnets ?? network.subnets(of: name).map(\.tincSubnetString)
            return Device(name: name, node: node, subnets: subnets, isMyself: false)
        }

        let query = searchText.lowercased()
        func matches(_ device: Device) -> Bool {
            query.isEmpty || device.name.lowercased().contains(query) || device.subnets.contains { $0.contains(query) }
        }

        let peers = names.sorted { $0.localizedStandardCompare($1) == .orderedAscending }.map(device).filter(matches)
        var sections: [DeviceSection] = []

        if let myName {
            let settings = network.loadSettings()
            let addresses = network.interfaceAddresses(settings).map(\.addressString)
            let me = Device(name: myName, node: status?.myself, subnets: addresses, isMyself: true)
            if matches(me) {
                sections.append(DeviceSection(title: "This device", devices: [me]))
            }
        }

        if status != nil {
            let online = peers.filter { $0.node?.reachable == true }
            let offline = peers.filter { $0.node?.reachable != true }
            if !online.isEmpty { sections.append(DeviceSection(title: "Online · \(online.count)", devices: online)) }
            if !offline.isEmpty { sections.append(DeviceSection(title: "Offline · \(offline.count)", devices: offline)) }
        } else if !peers.isEmpty {
            sections.append(DeviceSection(title: "Devices · \(peers.count)", devices: peers))
        }

        deviceSections = sections
        updateHeader(peerCount: names.count, onlineCount: status?.nodes.filter { $0.reachable && !$0.myself }.count)
        tableView.reloadData()
    }

    private func updateHeader(peerCount: Int, onlineCount: Int?) {
        let status = tunnel.configuredNetworkName == network?.name ? tunnel.status : .disconnected
        let color: UIColor
        switch status {
        case .connected: color = .meshOnline
        case .connecting, .reasserting, .disconnecting: color = .meshRelayed
        default: color = .meshOffline
        }
        var detail = "tinc \(TincCore.version) · SPTPS"
        if let onlineCount {
            detail += " · \(onlineCount) of \(peerCount) devices online"
        } else if let problem = network?.validate() {
            detail = problem
        } else {
            detail += " · \(peerCount) known devices"
        }
        header.configure(title: status == .invalid ? "Disconnected" : status.displayName, detail: detail, color: color)
        sizeHeaderToFit()
    }

    private func sizeHeaderToFit() {
        guard tableView.tableHeaderView === header else { return }
        let width = tableView.bounds.width
        let size = header.systemLayoutSizeFitting(CGSize(width: width, height: UIView.layoutFittingCompressedSize.height),
                                                  withHorizontalFittingPriority: .required,
                                                  verticalFittingPriority: .fittingSizeLevel)
        if header.frame.size.height != size.height || header.frame.width != width {
            header.frame = CGRect(x: 0, y: 0, width: width, height: size.height)
            tableView.tableHeaderView = header
        }
    }

    // MARK: - Navigation bar

    private func updateNavigationItems() {
        title = network?.name ?? "TincMesh"

        let networks = NetworkStore.shared.networks()
        var networkActions: [UIMenuElement] = networks.map { candidate in
            UIAction(title: candidate.name, subtitle: candidate.nodeName.map { "as \($0)" },
                     state: candidate.name == network?.name ? .on : .off) { [weak self] _ in
                self?.switchTo(candidate)
            }
        }
        networkActions.append(UIMenu(options: .displayInline, children: [
            UIAction(title: "Join with Invitation…", image: UIImage(systemName: "qrcode.viewfinder")) { [weak self] _ in self?.presentJoin() },
            UIAction(title: "Create Network…", image: UIImage(systemName: "plus.circle")) { [weak self] _ in self?.presentCreate() },
            UIAction(title: "Manage Networks…", image: UIImage(systemName: "list.bullet")) { [weak self] _ in
                self?.navigationController?.pushViewController(NetworksViewController(), animated: true)
            },
        ]))
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            image: UIImage(systemName: "point.3.connected.trianglepath.dotted"),
            menu: UIMenu(title: "Networks", children: networkActions))

        guard let network else {
            navigationItem.rightBarButtonItems = nil
            return
        }

        connectSwitch.isOn = tunnel.configuredNetworkName == network.name && tunnel.isActive
        connectSwitch.isEnabled = tunnel.status != .disconnecting
        let settings = UIBarButtonItem(image: UIImage(systemName: "gearshape"), primaryAction: UIAction { [weak self] _ in
            guard let self, let network = self.network else { return }
            self.navigationController?.pushViewController(NetworkSettingsViewController(network: network), animated: true)
        })
        navigationItem.rightBarButtonItems = [UIBarButtonItem(customView: connectSwitch), settings]
    }

    private func connectSwitchChanged() {
        guard let network else { return }
        if connectSwitch.isOn {
            tunnel.connect(to: network) { [weak self] error in
                if let error {
                    self?.connectSwitch.setOn(false, animated: true)
                    self?.showError(error, title: "Could not connect")
                }
            }
        } else if tunnel.isOnDemandEnabled {
            // Otherwise VPN On Demand would immediately reconnect.
            tunnel.setOnDemand(false) { [weak self] _ in self?.tunnel.disconnect() }
        } else {
            tunnel.disconnect()
        }
    }

    private func switchTo(_ candidate: TincNetwork) {
        let wasActive = tunnel.isActive
        NetworkStore.shared.activeNetwork = candidate
        reloadNetwork()
        if wasActive {
            tunnel.connect(to: candidate) { [weak self] error in
                if let error { self?.showError(error, title: "Could not connect") }
            }
        }
    }

    private func presentJoin() {
        present(UINavigationController(rootViewController: JoinNetworkViewController()), animated: true)
    }

    private func presentCreate() {
        present(UINavigationController(rootViewController: CreateNetworkViewController()), animated: true)
    }

    // MARK: - Search

    func updateSearchResults(for searchController: UISearchController) {
        searchText = searchController.searchBar.text ?? ""
        rebuild()
    }

    // MARK: - Table

    override func numberOfSections(in tableView: UITableView) -> Int {
        deviceSections.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        deviceSections[section].devices.count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        deviceSections[section].title
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let device = deviceSections[indexPath.section].devices[indexPath.row]
        let cell = tableView.dequeueReusableCell(withIdentifier: "device", for: indexPath)
        var content = UIListContentConfiguration.subtitleCell()
        content.text = device.name
        content.textProperties.font = .preferredFont(forTextStyle: .headline)

        var detail = device.subnets.isEmpty ? "No address" : device.subnets.joined(separator: ", ")
        let color: UIColor
        if let node = device.node {
            detail += " · " + Format.path(node)
            color = node.statusColor
        } else {
            color = device.isMyself && isConnectedToThisNetwork ? .meshOnline : .meshOffline
        }
        content.secondaryText = detail
        content.secondaryTextProperties.color = .secondaryLabel
        content.textToSecondaryTextVerticalPadding = 3
        content.image = UIImage(systemName: device.isMyself ? "iphone" : "circle.fill")
        content.imageProperties.tintColor = color
        content.imageProperties.maximumSize = device.isMyself ? CGSize(width: 22, height: 22) : CGSize(width: 10, height: 10)
        content.imageProperties.reservedLayoutSize = CGSize(width: 22, height: 22)
        cell.contentConfiguration = content
        cell.accessoryType = .disclosureIndicator
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard let network else { return }
        let device = deviceSections[indexPath.section].devices[indexPath.row]
        navigationController?.pushViewController(NodeDetailViewController(network: network, nodeName: device.name), animated: true)
    }

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath,
                            point: CGPoint) -> UIContextMenuConfiguration? {
        let device = deviceSections[indexPath.section].devices[indexPath.row]
        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            var actions: [UIMenuElement] = device.subnets.map { subnet in
                UIAction(title: "Copy \(subnet)", image: UIImage(systemName: "doc.on.doc")) { _ in
                    self?.copyToPasteboard(IPAddressRange(subnet)?.addressString ?? subnet)
                }
            }
            actions.append(UIAction(title: "Copy Name", image: UIImage(systemName: "textformat")) { _ in
                self?.copyToPasteboard(device.name)
            })
            return UIMenu(children: actions)
        }
    }
}

/// Connection status shown above the device list.
final class StatusHeaderView: UIView {
    private let dot = UIView()
    private let titleLabel = UILabel()
    private let detailLabel = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        dot.layer.cornerRadius = 6
        titleLabel.font = .preferredFont(forTextStyle: .title3).withTraits(.traitBold)
        titleLabel.adjustsFontForContentSizeCategory = true
        detailLabel.font = .preferredFont(forTextStyle: .footnote)
        detailLabel.textColor = .secondaryLabel
        detailLabel.numberOfLines = 0
        detailLabel.adjustsFontForContentSizeCategory = true

        let titleRow = UIStackView(arrangedSubviews: [dot, titleLabel])
        titleRow.spacing = 8
        titleRow.alignment = .center
        let stack = UIStackView(arrangedSubviews: [titleRow, detailLabel])
        stack.axis = .vertical
        stack.spacing = 4
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            dot.widthAnchor.constraint(equalToConstant: 12),
            dot.heightAnchor.constraint(equalToConstant: 12),
            stack.leadingAnchor.constraint(equalTo: layoutMarginsGuide.leadingAnchor, constant: 4),
            stack.trailingAnchor.constraint(equalTo: layoutMarginsGuide.trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 8),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    func configure(title: String, detail: String, color: UIColor) {
        titleLabel.text = title
        detailLabel.text = detail
        dot.backgroundColor = color
    }
}

/// Shown when no network has been set up yet.
final class WelcomeView: UIView {
    init(onJoin: @escaping () -> Void, onCreate: @escaping () -> Void) {
        super.init(frame: .zero)
        let icon = UIImageView(image: UIImage(systemName: "point.3.filled.connected.trianglepath.dotted"))
        icon.tintColor = .tintColor
        icon.preferredSymbolConfiguration = UIImage.SymbolConfiguration(pointSize: 56, weight: .light)
        icon.contentMode = .scaleAspectFit

        let title = UILabel()
        title.text = "Welcome to TincMesh"
        title.font = .preferredFont(forTextStyle: .title2).withTraits(.traitBold)
        title.textAlignment = .center

        let body = UILabel()
        body.text = "Connect this device to a tinc mesh VPN. Join an existing network with an invitation created with tinc invite, or start a new one."
        body.font = .preferredFont(forTextStyle: .body)
        body.textColor = .secondaryLabel
        body.numberOfLines = 0
        body.textAlignment = .center

        var joinConfig = UIButton.Configuration.filled()
        joinConfig.title = "Join with Invitation"
        joinConfig.image = UIImage(systemName: "qrcode.viewfinder")
        joinConfig.imagePadding = 8
        joinConfig.buttonSize = .large
        let join = UIButton(configuration: joinConfig, primaryAction: UIAction { _ in onJoin() })

        var createConfig = UIButton.Configuration.gray()
        createConfig.title = "Create a Network"
        createConfig.buttonSize = .large
        let create = UIButton(configuration: createConfig, primaryAction: UIAction { _ in onCreate() })

        let stack = UIStackView(arrangedSubviews: [icon, title, body, join, create])
        stack.axis = .vertical
        stack.spacing = 16
        stack.setCustomSpacing(28, after: body)
        stack.setCustomSpacing(10, after: join)
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: centerYAnchor, constant: -40),
            stack.leadingAnchor.constraint(equalTo: readableContentGuide.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: readableContentGuide.trailingAnchor, constant: -16),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }
}

extension UIFont {
    func withTraits(_ traits: UIFontDescriptor.SymbolicTraits) -> UIFont {
        guard let descriptor = fontDescriptor.withSymbolicTraits(traits) else { return self }
        return UIFont(descriptor: descriptor, size: 0)
    }
}
