import UIKit

/// A grouped table built from a declarative list of sections and rows,
/// used for the detail and settings screens.
class StaticTableViewController: UITableViewController {
    struct Row {
        enum Kind {
            /// Title with a trailing value; `copyable` rows copy the value on tap.
            case value(String?, copyable: Bool = false)
            /// Title with the value below it (long values such as keys).
            case subtitle(String?, copyable: Bool = false)
            case toggle(Bool, (Bool) -> Void)
            case navigation(String?)
            case button(destructive: Bool = false)
        }

        var title: String
        var kind: Kind
        var image: UIImage?
        var action: (() -> Void)?

        init(_ title: String, _ kind: Kind, image: UIImage? = nil, action: (() -> Void)? = nil) {
            self.title = title
            self.kind = kind
            self.image = image
            self.action = action
        }
    }

    struct Section {
        var title: String?
        var footer: String?
        var rows: [Row]

        init(_ title: String? = nil, footer: String? = nil, rows: [Row]) {
            self.title = title
            self.footer = footer
            self.rows = rows
        }
    }

    var sections: [Section] = [] {
        didSet { tableView.reloadData() }
    }

    init() {
        super.init(style: .insetGrouped)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        sections.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        sections[section].rows.count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        sections[section].title
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        sections[section].footer
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let row = sections[indexPath.section].rows[indexPath.row]
        let cell = UITableViewCell(style: .default, reuseIdentifier: nil)
        var content: UIListContentConfiguration
        cell.accessoryView = nil
        cell.accessoryType = .none
        cell.selectionStyle = .default

        switch row.kind {
        case .value(let value, _):
            content = .valueCell()
            content.secondaryText = value
        case .subtitle(let value, _):
            content = .subtitleCell()
            content.secondaryText = value
            content.secondaryTextProperties.font = .monospaced(.footnote)
            content.secondaryTextProperties.color = .secondaryLabel
            content.textToSecondaryTextVerticalPadding = 4
        case .toggle(let isOn, let changed):
            content = .cell()
            let toggle = UISwitch()
            toggle.isOn = isOn
            toggle.addAction(UIAction { action in
                changed((action.sender as? UISwitch)?.isOn ?? false)
            }, for: .valueChanged)
            cell.accessoryView = toggle
            cell.selectionStyle = .none
        case .navigation(let value):
            content = .valueCell()
            content.secondaryText = value
            cell.accessoryType = .disclosureIndicator
        case .button(let destructive):
            content = .cell()
            content.textProperties.color = destructive ? .systemRed : tintColorForButtons
        }

        content.text = row.title
        content.image = row.image
        if case .value(_, let copyable) = row.kind, !copyable, row.action == nil {
            cell.selectionStyle = .none
        }
        cell.contentConfiguration = content
        return cell
    }

    private var tintColorForButtons: UIColor {
        view.tintColor ?? .systemBlue
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let row = sections[indexPath.section].rows[indexPath.row]
        if let action = row.action {
            action()
            return
        }
        switch row.kind {
        case .value(let value?, true), .subtitle(let value?, true):
            copyToPasteboard(value, label: "Copied \(row.title.lowercased())")
        default:
            break
        }
    }
}
