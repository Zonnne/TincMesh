import CoreImage.CIFilterBuiltins
import UIKit

extension UIViewController {
    func showError(_ error: Error, title: String = "Something went wrong") {
        showAlert(title: title, message: error.localizedDescription)
    }

    func showAlert(title: String, message: String?) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    func confirm(title: String, message: String?, actionTitle: String, destructive: Bool = true,
                 sourceView: UIView? = nil, handler: @escaping () -> Void) {
        let sheet = UIAlertController(title: title, message: message, preferredStyle: .actionSheet)
        sheet.addAction(UIAlertAction(title: actionTitle, style: destructive ? .destructive : .default) { _ in handler() })
        sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        sheet.popoverPresentationController?.sourceView = sourceView ?? view
        if sourceView == nil {
            sheet.popoverPresentationController?.sourceRect = CGRect(x: view.bounds.midX, y: view.bounds.midY, width: 0, height: 0)
        }
        present(sheet, animated: true)
    }

    /// Shows a share sheet anchored to a bar button or view.
    func share(_ items: [Any], from barItem: UIBarButtonItem? = nil, sourceView: UIView? = nil) {
        let activity = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let barItem {
            activity.popoverPresentationController?.barButtonItem = barItem
        } else {
            activity.popoverPresentationController?.sourceView = sourceView ?? view
        }
        present(activity, animated: true)
    }

    func copyToPasteboard(_ text: String, label: String = "Copied") {
        UIPasteboard.general.string = text
        let feedback = UINotificationFeedbackGenerator()
        feedback.notificationOccurred(.success)
        Toast.show(label, in: view.window ?? view)
    }
}

/// A small transient confirmation bubble.
enum Toast {
    static func show(_ text: String, in view: UIView) {
        let label = PaddedLabel()
        label.text = text
        label.font = .preferredFont(forTextStyle: .subheadline)
        label.textColor = .systemBackground
        label.backgroundColor = UIColor.label.withAlphaComponent(0.85)
        label.layer.cornerRadius = 14
        label.layer.masksToBounds = true
        label.alpha = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
        ])
        UIView.animate(withDuration: 0.2, animations: { label.alpha = 1 }) { _ in
            UIView.animate(withDuration: 0.3, delay: 1.2, options: [], animations: { label.alpha = 0 }) { _ in
                label.removeFromSuperview()
            }
        }
    }

    private final class PaddedLabel: UILabel {
        override func drawText(in rect: CGRect) {
            super.drawText(in: rect.inset(by: UIEdgeInsets(top: 6, left: 14, bottom: 6, right: 14)))
        }

        override var intrinsicContentSize: CGSize {
            let size = super.intrinsicContentSize
            return CGSize(width: size.width + 28, height: size.height + 12)
        }
    }
}

enum Format {
    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter
    }()

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()

    static func bytes(_ count: Int64) -> String {
        byteFormatter.string(fromByteCount: count)
    }

    static func relative(epoch: Int, now: Int) -> String {
        guard epoch > 0 else { return "—" }
        return relativeFormatter.localizedString(for: Date(timeIntervalSince1970: TimeInterval(epoch)),
                                                 relativeTo: Date(timeIntervalSince1970: TimeInterval(now)))
    }

    static func path(_ node: MeshStatus.Node) -> String {
        switch node.path {
        case .myself: return "This device"
        case .offline: return "Offline"
        case .direct:
            if let rtt = node.rttMilliseconds { return String(format: "Direct · %.0f ms", rtt) }
            return "Direct"
        case .relayed(let via): return "Relayed via \(via)"
        case .tcp(let via): return via == node.name ? "TCP" : "TCP via \(via)"
        }
    }
}

enum QRCode {
    static func image(for text: String, size: CGFloat = 240) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scale = size / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        guard let cgImage = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

extension UIColor {
    static let meshOnline = UIColor.systemGreen
    static let meshRelayed = UIColor.systemOrange
    static let meshOffline = UIColor.systemGray3
}

extension MeshStatus.Node {
    var statusColor: UIColor {
        switch path {
        case .myself, .direct: return .meshOnline
        case .relayed, .tcp: return .meshRelayed
        case .offline: return .meshOffline
        }
    }
}

extension UIFont {
    static func monospaced(_ style: UIFont.TextStyle) -> UIFont {
        let size = UIFont.preferredFont(forTextStyle: style).pointSize
        return UIFontMetrics(forTextStyle: style).scaledFont(for: .monospacedSystemFont(ofSize: size, weight: .regular))
    }
}
