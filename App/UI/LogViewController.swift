import UIKit

/// Shows tinc's log, written by the extension into the App Group container.
final class LogViewController: UIViewController {
    private let textView = UITextView()
    private var timer: Timer?
    private var lastSize: UInt64 = .max

    /// Only the end of the log is shown; tinc rotates it at about 1 MB.
    private static let tailBytes: UInt64 = 128 * 1024

    init() {
        super.init(nibName: nil, bundle: nil)
        title = "Log"
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationItem.largeTitleDisplayMode = .never
        view.backgroundColor = .systemBackground

        textView.isEditable = false
        textView.font = .monospaced(.caption2)
        textView.adjustsFontForContentSizeCategory = true
        textView.alwaysBounceVertical = true
        textView.textContainerInset = UIEdgeInsets(top: 8, left: 6, bottom: 8, right: 6)
        textView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textView)
        NSLayoutConstraint.activate([
            textView.topAnchor.constraint(equalTo: view.topAnchor),
            textView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])

        let share = UIBarButtonItem(systemItem: .action, primaryAction: UIAction { [weak self] action in
            self?.share([AppGroup.logURL], from: action.sender as? UIBarButtonItem)
        })
        let clear = UIBarButtonItem(systemItem: .trash, primaryAction: UIAction { [weak self] _ in self?.clear() })
        navigationItem.rightBarButtonItems = [share, clear]
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reload(scrollToEnd: true)
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.reload(scrollToEnd: false) }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        timer?.invalidate()
        timer = nil
    }

    private func reload(scrollToEnd: Bool) {
        let size = (try? FileManager.default.attributesOfItem(atPath: AppGroup.logURL.path)[.size] as? UInt64) ?? 0
        guard size != lastSize else { return }
        lastSize = size

        let wasAtEnd = textView.contentOffset.y >= textView.contentSize.height - textView.bounds.height - 40
        let text = Self.readTail()
        textView.text = text.isEmpty ? "No log yet. Connect to a network to start tinc." : text
        if scrollToEnd || wasAtEnd {
            textView.layoutIfNeeded()
            textView.scrollRangeToVisible(NSRange(location: (textView.text as NSString).length, length: 0))
        }
    }

    private static func readTail() -> String {
        var data = Data()
        for url in [AppGroup.rotatedLogURL, AppGroup.logURL] {
            if let contents = try? Data(contentsOf: url) {
                data.append(contents)
            }
        }
        if data.count > Int(tailBytes) {
            data = data.suffix(Int(tailBytes))
            // Start at a line boundary.
            if let newline = data.firstIndex(of: UInt8(ascii: "\n")) {
                data = data[(newline + 1)...]
            }
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func clear() {
        // The extension appends to the open file, so truncate rather than delete it.
        for url in [AppGroup.logURL, AppGroup.rotatedLogURL] {
            if let handle = try? FileHandle(forWritingTo: url) {
                try? handle.truncate(atOffset: 0)
                try? handle.close()
            }
        }
        lastSize = .max
        reload(scrollToEnd: true)
    }
}
