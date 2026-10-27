import UIKit

/// A plain monospaced editor for tinc configuration files.
final class TextEditorViewController: UIViewController, UITextViewDelegate {
    private let url: URL
    private let onSave: () -> Void
    private let validate: ((String) -> String?)?
    private let textView = UITextView()
    private var original = ""
    private let initialText: String?

    /// `validate` returns an error message to block saving, or nil if the text is fine.
    init(title: String, url: URL, initialText: String? = nil,
         validate: ((String) -> String?)? = nil, onSave: @escaping () -> Void = {}) {
        self.url = url
        self.onSave = onSave
        self.validate = validate
        self.initialText = initialText
        super.init(nibName: nil, bundle: nil)
        self.title = title
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        view.backgroundColor = .systemBackground

        textView.font = .monospaced(.callout)
        textView.adjustsFontForContentSizeCategory = true
        textView.autocapitalizationType = .none
        textView.autocorrectionType = .no
        textView.spellCheckingType = .no
        textView.smartQuotesType = .no
        textView.smartDashesType = .no
        textView.smartInsertDeleteType = .no
        textView.alwaysBounceVertical = true
        textView.keyboardDismissMode = .interactive
        textView.textContainerInset = UIEdgeInsets(top: 12, left: 8, bottom: 12, right: 8)
        textView.delegate = self
        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: view.topAnchor),
            textView.bottomAnchor.constraint(equalTo: view.keyboardLayoutGuide.topAnchor),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])

        original = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        textView.text = original.isEmpty ? (initialText ?? "") : original

        navigationItem.rightBarButtonItem = UIBarButtonItem(systemItem: .save, primaryAction: UIAction { [weak self] _ in
            self?.save()
        })
        navigationItem.rightBarButtonItem?.isEnabled = textView.text != original
    }

    func textViewDidChange(_ textView: UITextView) {
        navigationItem.rightBarButtonItem?.isEnabled = textView.text != original
    }

    private func save() {
        var text = textView.text ?? ""
        if !text.isEmpty && !text.hasSuffix("\n") {
            text += "\n"
        }
        if let problem = validate?(text) {
            showAlert(title: "Not saved", message: problem)
            return
        }
        do {
            try Data(text.utf8).write(to: url, options: .atomic)
            original = text
            navigationItem.rightBarButtonItem?.isEnabled = false
            onSave()
            Toast.show("Saved", in: view.window ?? view)
        } catch {
            showError(error, title: "Could not save")
        }
    }
}
