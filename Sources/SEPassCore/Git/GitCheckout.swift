import Foundation

/// Walks a resolved object set from a commit down to its tree and writes the working
/// tree to disk. SE Pass only needs the file contents of a pass store (blobs + nested
/// trees); submodules are skipped.
enum GitCheckout {
    static func checkout(commitSha: String, objects: [String: GitObject], into dir: URL) throws {
        guard let commit = objects[commitSha], commit.type == .commit else {
            throw GitError.packError("commit \(commitSha) not in pack")
        }
        guard let treeSha = treeSha(ofCommit: commit.data) else {
            throw GitError.packError("commit has no tree")
        }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try writeTree(treeSha, objects: objects, into: dir)
    }

    /// The "tree <sha>" line at the top of a commit object.
    private static func treeSha(ofCommit data: [UInt8]) -> String? {
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n") {
            if line.hasPrefix("tree ") { return String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces) }
            if line.isEmpty { break } // header ends at the blank line
        }
        return nil
    }

    private static func writeTree(_ treeSha: String, objects: [String: GitObject], into dir: URL) throws {
        guard let tree = objects[treeSha], tree.type == .tree else {
            throw GitError.packError("tree \(treeSha) not in pack")
        }
        for entry in parseTree(tree.data) {
            let dest = dir.appendingPathComponent(entry.name)
            switch entry.mode {
            case "40000", "040000": // directory
                try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true)
                try writeTree(entry.sha, objects: objects, into: dest)
            case "160000": // submodule gitlink — nothing to write
                continue
            default: // 100644 / 100755 blob, or 120000 symlink (written as a regular file)
                guard let blob = objects[entry.sha], blob.type == .blob else {
                    throw GitError.packError("blob \(entry.sha) not in pack")
                }
                try Data(blob.data).write(to: dest)
            }
        }
    }

    private struct TreeEntry { let mode: String; let name: String; let sha: String }

    /// Tree object: repeated "<mode> <name>\0<20-byte sha>".
    private static func parseTree(_ data: [UInt8]) -> [TreeEntry] {
        var entries: [TreeEntry] = []
        var i = 0
        while i < data.count {
            var j = i
            while j < data.count, data[j] != 0x20 { j += 1 } // space ends mode
            let mode = String(decoding: data[i..<j], as: UTF8.self)
            i = j + 1
            var k = i
            while k < data.count, data[k] != 0x00 { k += 1 } // NUL ends name
            let name = String(decoding: data[i..<k], as: UTF8.self)
            i = k + 1
            let sha = data[i..<i + 20].map { String(format: "%02x", $0) }.joined()
            i += 20
            entries.append(TreeEntry(mode: mode, name: name, sha: sha))
        }
        return entries
    }
}
