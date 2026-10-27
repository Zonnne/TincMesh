import UIKit

/// Rule-based routing for one network: send chosen sites through chosen
/// nodes (e.g. one exit node for streaming, another for work), configured
/// with Shadowrocket-style rules in rules.conf.
final class RulesViewController: StaticTableViewController {
    private let network: TincNetwork
    private var liveStatus: PolicyStatus?
    private var timer: Timer?

    init(network: TincNetwork) {
        self.network = network
        super.init()
        title = "Routing Rules"
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
        refreshLive()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refreshLive() }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        timer?.invalidate()
        timer = nil
    }

    private var isConnected: Bool {
        let tunnel = TunnelController.shared
        return tunnel.status == .connected && tunnel.configuredNetworkName == network.name
    }

    private func refreshLive() {
        guard isConnected else {
            if liveStatus != nil {
                liveStatus = nil
                rebuild()
            }
            return
        }
        TunnelController.shared.fetchStatus { [weak self] status in
            guard let self, status?.policy != self.liveStatus else { return }
            self.liveStatus = status?.policy
            self.rebuild()
        }
    }

    // MARK: - Sections

    private func rebuild() {
        let settings = network.loadSettings()
        let text = network.loadRules()
        var result: [Section] = []

        result.append(Section(
            footer: "Domain rules work through DNS: matching names get a stand-in address from 198.18.0.0/15, and their real address is looked up through the chosen node. Each connection stays on the node it started on.",
            rows: [
                Row("Rule-Based Routing", .toggle(settings.rulesEnabled, { [weak self] on in self?.setEnabled(on) })),
            ]))

        var ruleRows: [Row] = [
            Row(text == nil ? "Create Rules…" : "Edit Rules", .navigation(nil), image: UIImage(systemName: "list.bullet.rectangle")) { [weak self] in
                self?.editRules()
            },
        ]
        var summarySection: Section?

        if let text {
            do {
                let summary = try TincCore.checkRules(PolicyRules.effectiveText(text, settings: settings))
                ruleRows.append(Row("Rules", .value("\(summary.rules)")))
                ruleRows.append(Row("Everything else", .value(summary.final)))
                summarySection = makeSummarySection(summary)
            } catch {
                ruleRows.append(Row("Error", .subtitle(error.localizedDescription)))
            }
        }

        result.append(Section("Rules", footer: "Rules use the Shadowrocket format: [General], [Proxy Group] and [Rule] sections with DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6 and FINAL. Policies are tinc node names, groups, DIRECT or REJECT.", rows: ruleRows))

        if let summarySection {
            result.append(summarySection)
        }

        if let live = liveStatus, live.enabled {
            var rows: [Row] = [
                Row("Active connections", .value("\(live.flows ?? 0)")),
                Row("Names resolved via nodes", .value("\(live.dnsFake ?? 0)")),
                Row("Names resolved directly", .value("\(live.dnsDirect ?? 0)")),
            ]
            if let failed = live.dnsFailed, failed > 0 {
                rows.append(Row("Failed lookups", .value("\(failed)")))
            }
            if let rejected = live.dnsRejected, rejected > 0 {
                rows.append(Row("Blocked lookups", .value("\(rejected)")))
            }
            for group in live.groups ?? [] {
                rows.append(Row(group.name, .value(group.selected ?? "No node reachable"), image: UIImage(systemName: "arrow.triangle.branch")))
            }
            result.append(Section("Live", rows: rows))
        }

        result.append(Section(
            "Exit nodes",
            footer: """
            A node that carries traffic to the Internet needs, on its own machine:
            • Forwarding = kernel in tinc.conf
            • IP forwarding enabled (sysctl net.ipv4.ip_forward=1)
            • NAT for the VPN's addresses, e.g. iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
            """,
            rows: []))

        sections = result
    }

    private func makeSummarySection(_ summary: PolicyRules.Summary) -> Section {
        var rows: [Row] = []
        if summary.captureAllDns {
            rows.append(Row("DNS", .value("All lookups checked")))
        } else if !summary.matchDomains.isEmpty {
            rows.append(Row("Domains", .subtitle(summary.matchDomains.joined(separator: ", "))))
        }
        if !summary.includeRoutes.isEmpty {
            rows.append(Row("Routed addresses", .subtitle(summary.includeRoutes.joined(separator: ", "))))
        }
        if !summary.excludeRoutes.isEmpty {
            rows.append(Row("Direct addresses", .subtitle(summary.excludeRoutes.joined(separator: ", "))))
        }
        if !summary.nodes.isEmpty {
            rows.append(Row("Nodes used", .subtitle(summary.nodes.joined(separator: ", "))))
        }
        if !summary.groups.isEmpty {
            rows.append(Row("Groups", .subtitle(summary.groups.joined(separator: ", "))))
        }
        for warning in summary.warnings {
            rows.append(Row("Warning", .subtitle(warning), image: UIImage(systemName: "exclamationmark.triangle")))
        }
        return Section("Summary", rows: rows)
    }

    // MARK: - Actions

    private func setEnabled(_ on: Bool) {
        var settings = network.loadSettings()
        if on, network.loadRules() == nil {
            // Nothing to enable yet: start from the template.
            editRules()
            rebuild()
            return
        }
        settings.rulesEnabled = on
        do {
            try network.saveSettings(settings)
            applyToTunnel()
        } catch {
            showError(error)
        }
        rebuild()
    }

    private func editRules() {
        let settings = network.loadSettings()
        let editor = TextEditorViewController(
            title: PolicyRules.fileName,
            url: network.rulesURL,
            initialText: PolicyRules.template,
            validate: { text in
                do {
                    _ = try TincCore.checkRules(PolicyRules.effectiveText(text, settings: settings))
                    return nil
                } catch {
                    return error.localizedDescription
                }
            },
            onSave: { [weak self] in
                guard let self else { return }
                var settings = self.network.loadSettings()
                if !settings.rulesEnabled {
                    settings.rulesEnabled = true
                    try? self.network.saveSettings(settings)
                }
                self.applyToTunnel()
            })
        navigationController?.pushViewController(editor, animated: true)
    }

    /// Rules change routes and DNS capture, which the running extension applies live.
    private func applyToTunnel() {
        guard isConnected else { return }
        TunnelController.shared.send(.reloadRules) { [weak self] _ in
            self?.refreshLive()
        }
    }
}
