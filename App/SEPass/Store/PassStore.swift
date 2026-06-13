import Foundation

/// A node in the pass tree: either a folder or a password entry (a `.gpg` file).
/// Entry *names* are plaintext in pass, so the whole tree and search work without any
/// decryption.
struct PassNode: Identifiable, Hashable {
    let id: String          // path relative to the store root, without the .gpg suffix
    let name: String        // display name (last path component)
    let url: URL            // absolute file URL (for entries)
    let isFolder: Bool
    var children: [PassNode]

    /// For `OutlineGroup`: folders expose children, leaves return nil.
    var childrenOrNil: [PassNode]? { isFolder ? children : nil }
}

/// Reads the on-disk pass store (the cloned git working tree) into a navigable tree.
struct PassStore {
    let root: URL

    /// Build the tree, skipping the `.git` directory and pass metadata files.
    func load() -> [PassNode] {
        buildChildren(of: root, prefix: "")
    }

    private func buildChildren(of dir: URL, prefix: String) -> [PassNode] {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return []
        }
        var nodes: [PassNode] = []
        for url in entries {
            let name = url.lastPathComponent
            if name == ".git" { continue }
            let isDir = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDir {
                let relPath = prefix.isEmpty ? name : "\(prefix)/\(name)"
                let children = buildChildren(of: url, prefix: relPath)
                if !children.isEmpty {
                    nodes.append(PassNode(id: relPath, name: name, url: url, isFolder: true, children: children))
                }
            } else if name.hasSuffix(".gpg") {
                let base = String(name.dropLast(4))
                let relPath = prefix.isEmpty ? base : "\(prefix)/\(base)"
                nodes.append(PassNode(id: relPath, name: base, url: url, isFolder: false, children: []))
            }
        }
        return nodes.sorted { ($0.isFolder ? 0 : 1, $0.name.lowercased()) < ($1.isFolder ? 0 : 1, $1.name.lowercased()) }
    }

    /// Flatten all entries (leaves) for name search.
    static func allEntries(_ nodes: [PassNode]) -> [PassNode] {
        nodes.flatMap { $0.isFolder ? allEntries($0.children) : [$0] }
    }
}
