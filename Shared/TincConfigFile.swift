import Foundation

/// A tinc configuration file (`tinc.conf` or `hosts/NAME`).
///
/// Parsing follows tinc's `parse_config_line()`: a variable name, then
/// optional whitespace, an optional `=`, and the value. Variable names are
/// case-insensitive, `#` starts a comment, and PEM blocks (public keys in
/// host files) are skipped. Edits keep comments, ordering and PEM blocks
/// intact so files remain friendly to hand editing and to desktop tinc.
struct TincConfigFile {
    struct Entry {
        let key: String
        let value: String
        let lineIndex: Int
    }

    private(set) var lines: [String]

    init(text: String = "") {
        var lines = text.components(separatedBy: "\n").map { line in
            line.hasSuffix("\r") ? String(line.dropLast()) : line
        }
        if lines.last == "" {
            lines.removeLast()
        }
        self.lines = lines
    }

    init(contentsOf url: URL) throws {
        self.init(text: try String(contentsOf: url, encoding: .utf8))
    }

    var text: String {
        lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    }

    func write(to url: URL) throws {
        try Data(text.utf8).write(to: url, options: .atomic)
    }

    var entries: [Entry] {
        var result: [Entry] = []
        var inPEM = false
        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if inPEM {
                if trimmed.hasPrefix("-----END") { inPEM = false }
                continue
            }
            if trimmed.hasPrefix("-----BEGIN") {
                inPEM = true
                continue
            }
            if let (key, value) = Self.parse(line: trimmed) {
                result.append(Entry(key: key, value: value, lineIndex: index))
            }
        }
        return result
    }

    static func parse(line: String) -> (String, String)? {
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
        let separators = CharacterSet(charactersIn: "\t =")
        guard let keyEnd = line.rangeOfCharacter(from: separators) else { return nil }
        let key = String(line[..<keyEnd.lowerBound])
        var rest = line[keyEnd.lowerBound...].drop { $0 == " " || $0 == "\t" }
        if rest.first == "=" {
            rest = rest.dropFirst().drop { $0 == " " || $0 == "\t" }
        }
        let value = rest.trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty, !value.isEmpty else { return nil }
        return (key, value)
    }

    func values(_ key: String) -> [String] {
        entries.filter { $0.key.caseInsensitiveCompare(key) == .orderedSame }.map(\.value)
    }

    func value(_ key: String) -> String? {
        values(key).first
    }

    func bool(_ key: String) -> Bool? {
        guard let value = value(key)?.lowercased() else { return nil }
        return value == "yes" || value == "true" || value == "1"
    }

    /// Replaces all occurrences of `key` with a single line, or removes them when `value` is nil.
    mutating func set(_ key: String, _ value: String?) {
        setAll(key, value.map { [$0] } ?? [])
    }

    /// Replaces all occurrences of `key`. New lines go where the first old one was,
    /// or before any PEM block, or at the end.
    mutating func setAll(_ key: String, _ values: [String]) {
        let matching = entries.filter { $0.key.caseInsensitiveCompare(key) == .orderedSame }
        var insertAt = matching.first?.lineIndex ?? firstPEMLine ?? lines.count
        for entry in matching.reversed() {
            lines.remove(at: entry.lineIndex)
            if entry.lineIndex < insertAt { insertAt -= 1 }
        }
        let canonical = matching.first?.key ?? key
        lines.insert(contentsOf: values.map { "\(canonical) = \($0)" }, at: min(insertAt, lines.count))
    }

    mutating func append(_ key: String, _ value: String) {
        lines.insert("\(key) = \(value)", at: firstPEMLine ?? lines.count)
    }

    private var firstPEMLine: Int? {
        lines.firstIndex { $0.trimmingCharacters(in: .whitespaces).hasPrefix("-----BEGIN") }
    }

    /// Valid tinc node names contain only ASCII letters, digits and underscores.
    static func isValidNodeName(_ name: String) -> Bool {
        !name.isEmpty && name.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_")
        }
    }
}
