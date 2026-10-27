import UIKit

/// Edits a list of strings (addresses, routes, DNS servers, node names).
final class ListEditorViewController: UITableViewController {
    private var values: [String]
    private let placeholder: String
    private let validate: (String) -> Bool
    private let onChange: ([String]) -> Void

    init(title: String, values: [String], placeholder: String,
         validate: @escaping (String) -> Bool, onChange: @escaping ([String]) -> Void) {
        self.values = values
        self.placeholder = placeholder
        self.validate = validate
        self.onChange = onChange
        super.init(style: .insetGrouped)
        self.title = title
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(systemItem: .add, primaryAction: UIAction { [weak self] _ in self?.addValue() }),
            editButtonItem,
        ]
    }

    private func addValue() {
        let alert = UIAlertController(title: "Add", message: nil, preferredStyle: .alert)
        alert.addTextField { [placeholder] field in
            field.placeholder = placeholder
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
            field.keyboardType = .numbersAndPunctuation
            field.font = .monospaced(.body)
        }
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        alert.addAction(UIAlertAction(title: "Add", style: .default) { [weak self, weak alert] _ in
            guard let self else { return }
            let text = alert?.textFields?.first?.text?.trimmingCharacters(in: .whitespaces) ?? ""
            guard !text.isEmpty, self.validate(text) else {
                self.showAlert(title: "Invalid value", message: "“\(text)” is not valid here.")
                return
            }
            guard !self.values.contains(text) else { return }
            self.values.append(text)
            self.tableView.insertRows(at: [IndexPath(row: self.values.count - 1, section: 0)], with: .automatic)
            self.onChange(self.values)
        })
        present(alert, animated: true)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        values.count
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        values.isEmpty ? "Nothing configured. Tap + to add." : nil
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .default, reuseIdentifier: nil)
        var content = cell.defaultContentConfiguration()
        content.text = values[indexPath.row]
        content.textProperties.font = .monospaced(.body)
        cell.contentConfiguration = content
        cell.selectionStyle = .none
        return cell
    }

    override func tableView(_ tableView: UITableView, commit editingStyle: UITableViewCell.EditingStyle,
                            forRowAt indexPath: IndexPath) {
        guard editingStyle == .delete else { return }
        values.remove(at: indexPath.row)
        tableView.deleteRows(at: [indexPath], with: .automatic)
        onChange(values)
    }

    override func tableView(_ tableView: UITableView, moveRowAt source: IndexPath, to destination: IndexPath) {
        let value = values.remove(at: source.row)
        values.insert(value, at: destination.row)
        onChange(values)
    }
}
