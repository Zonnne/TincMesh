import UIKit

/// A simple form of labelled text fields with an asynchronous submit action.
/// While submitting, the Done button turns into a spinner and fields are locked.
class FormViewController: UITableViewController, UITextFieldDelegate {
    struct Field {
        let key: String
        let label: String
        var placeholder: String = ""
        var text: String = ""
        var keyboard: UIKeyboardType = .default
        var footer: String?
        var monospaced = false
    }

    private(set) var fields: [Field]
    private var textFields: [String: UITextField] = [:]
    private let submitTitle: String
    /// Called with trimmed field values keyed by `Field.key`. Throw to show an error.
    var submitHandler: ([String: String]) async throws -> Void
    private var isSubmitting = false

    /// `submit` receives trimmed field values keyed by `Field.key`. Throw to show an error.
    init(title: String, fields: [Field], submitTitle: String = "Done",
         submit: @escaping ([String: String]) async throws -> Void) {
        self.fields = fields
        self.submitTitle = submitTitle
        self.submitHandler = submit
        super.init(style: .insetGrouped)
        self.title = title
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        tableView.keyboardDismissMode = .interactive
        if navigationController?.viewControllers.first === self {
            navigationItem.leftBarButtonItem = UIBarButtonItem(systemItem: .cancel, primaryAction: UIAction { [weak self] _ in
                self?.dismiss(animated: true)
            })
        }
        setSubmitButton()
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        if let first = fields.first(where: { $0.text.isEmpty }) ?? fields.first {
            textFields[first.key]?.becomeFirstResponder()
        }
    }

    private func setSubmitButton() {
        let item = UIBarButtonItem(title: submitTitle, primaryAction: UIAction { [weak self] _ in self?.runSubmit() })
        item.style = .done
        navigationItem.rightBarButtonItem = item
    }

    func value(for key: String) -> String {
        (textFields[key]?.text ?? fields.first { $0.key == key }?.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func setValue(_ value: String, for key: String) {
        if let index = fields.firstIndex(where: { $0.key == key }) {
            fields[index].text = value
        }
        textFields[key]?.text = value
    }

    private func runSubmit() {
        guard !isSubmitting else { return }
        view.endEditing(true)
        var values: [String: String] = [:]
        for field in fields {
            values[field.key] = value(for: field.key)
        }

        isSubmitting = true
        let spinner = UIActivityIndicatorView(style: .medium)
        spinner.startAnimating()
        navigationItem.rightBarButtonItem = UIBarButtonItem(customView: spinner)
        textFields.values.forEach { $0.isEnabled = false }

        Task { @MainActor in
            do {
                try await submitHandler(values)
            } catch {
                showError(error)
            }
            isSubmitting = false
            textFields.values.forEach { $0.isEnabled = true }
            setSubmitButton()
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        fields.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        1
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        fields[section].label
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        fields[section].footer
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let field = fields[indexPath.section]
        let cell = UITableViewCell(style: .default, reuseIdentifier: nil)
        cell.selectionStyle = .none

        let textField = textFields[field.key] ?? UITextField()
        textField.text = textFields[field.key]?.text ?? field.text
        textField.placeholder = field.placeholder
        textField.keyboardType = field.keyboard
        textField.autocapitalizationType = .none
        textField.autocorrectionType = .no
        textField.spellCheckingType = .no
        textField.clearButtonMode = .whileEditing
        textField.font = field.monospaced ? .monospaced(.body) : .preferredFont(forTextStyle: .body)
        textField.adjustsFontForContentSizeCategory = true
        textField.returnKeyType = indexPath.section == fields.count - 1 ? .done : .next
        textField.delegate = self
        textField.tag = indexPath.section
        textFields[field.key] = textField

        textField.translatesAutoresizingMaskIntoConstraints = false
        cell.contentView.addSubview(textField)
        NSLayoutConstraint.activate([
            textField.leadingAnchor.constraint(equalTo: cell.contentView.layoutMarginsGuide.leadingAnchor),
            textField.trailingAnchor.constraint(equalTo: cell.contentView.layoutMarginsGuide.trailingAnchor),
            textField.topAnchor.constraint(equalTo: cell.contentView.topAnchor, constant: 11),
            textField.bottomAnchor.constraint(equalTo: cell.contentView.bottomAnchor, constant: -11),
        ])
        return cell
    }

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        let next = textField.tag + 1
        if next < fields.count, let nextField = textFields[fields[next].key] {
            nextField.becomeFirstResponder()
        } else {
            runSubmit()
        }
        return true
    }
}
