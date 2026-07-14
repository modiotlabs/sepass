import Foundation
import SEPassCore

/// How to authenticate to a remote. Local/unauthenticated remotes use `.none`.
enum GitCredential: Codable, Hashable {
    case none
    case httpsToken(username: String, token: String)
    case sshKey(privateKeyPEM: String, passphrase: String?)
    case sshPassword(username: String, password: String)
}

/// User-supplied remote configuration. The URL drives everything; credentials are
/// optional (a local or public repo needs none).
struct GitRemote: Codable, Hashable {
    var url: String
    var credential: GitCredential = .none
    var branch: String = ""   // empty = the remote's default branch
    /// The Sync screen's selected auth mode, remembered across launches. Optional so
    /// settings saved before this field existed still decode.
    var authMode: String?
}

enum SyncError: LocalizedError {
    case invalidURL
    case unsupportedScheme(String)
    case sshNoKey
    case writeNotSupported

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "That doesn't look like a valid git URL."
        case .unsupportedScheme(let s): return "Unsupported URL scheme: \(s)."
        case .sshNoKey: return "Generate an SSH key first (Sync → SSH auth → Generate)."
        case .writeNotSupported: return "SE Pass is read-only; it clones but doesn't push."
        }
    }
}

/// The git operations SE Pass needs. Clone + refresh only (no on-device edits).
protocol GitService {
    /// Clone the working tree into `destination`, returning the cloned commit id.
    @discardableResult
    func clone(_ remote: GitRemote, into destination: URL) async throws -> String
    /// The commit id the remote currently points at, fetched from the ref advertisement
    /// alone (no packfile). Lets the app skip a refresh when nothing has changed.
    func remoteHead(_ remote: GitRemote) async throws -> String
    func pull(_ remote: GitRemote, at repo: URL) async throws
    func push(_ remote: GitRemote, at repo: URL) async throws
}

/// Clone-only git backed by SEPassCore's pure-Swift client (no libgit2). HTTPS works
/// today via URLSession; SSH is wired once the swift-nio-ssh transport lands.
struct PureGitService: GitService {
    /// Supplied by the app to build an SSH transport with the Secure-Enclave SSH key.
    var sshTransportFactory: ((_ host: String, _ port: Int, _ user: String, _ path: String) throws -> GitUploadPackTransport)?

    @discardableResult
    func clone(_ remote: GitRemote, into destination: URL) async throws -> String {
        let (transport, ref) = try makeTransport(remote)
        return try await GitCloner(transport: transport).clone(ref: ref, into: destination)
    }

    func remoteHead(_ remote: GitRemote) async throws -> String {
        let (transport, ref) = try makeTransport(remote)
        return try await GitCloner(transport: transport).remoteHead(ref: ref)
    }

    /// Clone-only, so "pull" simply re-fetches the working tree.
    func pull(_ remote: GitRemote, at repo: URL) async throws {
        let fresh = repo.deletingLastPathComponent().appendingPathComponent(".store-refresh")
        try? FileManager.default.removeItem(at: fresh)
        try await clone(remote, into: fresh)
        try? FileManager.default.removeItem(at: repo)
        try FileManager.default.moveItem(at: fresh, to: repo)
    }

    func push(_ remote: GitRemote, at repo: URL) async throws { throw SyncError.writeNotSupported }

    /// Builds the upload-pack transport for `remote` plus the ref to request (nil = the
    /// remote's default branch). Shared by clone and remoteHead so both authenticate and
    /// address the repo identically.
    private func makeTransport(_ remote: GitRemote) throws -> (GitUploadPackTransport, String?) {
        let raw = remote.url.trimmingCharacters(in: .whitespaces)
        let ref = remote.branch.isEmpty ? nil : remote.branch

        // scp-style SSH: user@host:path (no scheme).
        if let ssh = Self.parseSCPStyle(raw) {
            return (try makeSSH(host: ssh.host, port: ssh.port, user: ssh.user, path: ssh.path), ref)
        }

        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased() else { throw SyncError.invalidURL }
        switch scheme {
        case "https", "http":
            var username: String?, secret: String?
            if case .httpsToken(let u, let t) = remote.credential { username = u; secret = t }
            return (HTTPSUploadPackTransport(repoURL: url, username: username, password: secret), ref)
        case "ssh":
            // Preserve url.path verbatim (including a leading "/") so absolute server
            // paths like ssh://foo@host/some/repo stay absolute. Hosts that want a
            // home-relative path use the ~ form (ssh://host/~/repo), which is preserved too.
            return (try makeSSH(host: url.host ?? "", port: url.port ?? 22,
                                user: url.user ?? "git", path: url.path), ref)
        default:
            throw SyncError.unsupportedScheme(scheme)
        }
    }

    private func makeSSH(host: String, port: Int, user: String, path: String) throws -> GitUploadPackTransport {
        guard let factory = sshTransportFactory else { throw SyncError.sshNoKey }
        return try factory(host, port, user, path)
    }

    /// Parse "user@host:path" (scp-style), returning nil for anything with a "://" scheme.
    static func parseSCPStyle(_ s: String) -> (user: String, host: String, port: Int, path: String)? {
        guard !s.contains("://"), let at = s.firstIndex(of: "@") else { return nil }
        let user = String(s[..<at])
        let rest = s[s.index(after: at)...]
        guard let colon = rest.firstIndex(of: ":") else { return nil }
        let host = String(rest[..<colon])
        let path = String(rest[rest.index(after: colon)...])
        guard !user.isEmpty, !host.isEmpty, !path.isEmpty else { return nil }
        return (user, host, 22, path)
    }
}
