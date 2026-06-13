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
    func clone(_ remote: GitRemote, into destination: URL) async throws
    func pull(_ remote: GitRemote, at repo: URL) async throws
    func push(_ remote: GitRemote, at repo: URL) async throws
}

/// Clone-only git backed by SEPassCore's pure-Swift client (no libgit2). HTTPS works
/// today via URLSession; SSH is wired once the swift-nio-ssh transport lands.
struct PureGitService: GitService {
    /// Supplied by the app to build an SSH transport with the Secure-Enclave SSH key.
    var sshTransportFactory: ((_ host: String, _ port: Int, _ user: String, _ path: String) throws -> GitUploadPackTransport)?

    func clone(_ remote: GitRemote, into destination: URL) async throws {
        try await fetch(remote, into: destination)
    }

    /// Clone-only, so "pull" simply re-fetches the working tree.
    func pull(_ remote: GitRemote, at repo: URL) async throws {
        let fresh = repo.deletingLastPathComponent().appendingPathComponent(".store-refresh")
        try? FileManager.default.removeItem(at: fresh)
        try await fetch(remote, into: fresh)
        try? FileManager.default.removeItem(at: repo)
        try FileManager.default.moveItem(at: fresh, to: repo)
    }

    func push(_ remote: GitRemote, at repo: URL) async throws { throw SyncError.writeNotSupported }

    private func fetch(_ remote: GitRemote, into destination: URL) async throws {
        let raw = remote.url.trimmingCharacters(in: .whitespaces)
        let ref = remote.branch.isEmpty ? nil : remote.branch

        // scp-style SSH: user@host:path (no scheme).
        if let ssh = Self.parseSCPStyle(raw) {
            let transport = try makeSSH(host: ssh.host, port: ssh.port, user: ssh.user, path: ssh.path)
            try await GitCloner(transport: transport).clone(ref: ref, into: destination)
            return
        }

        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased() else { throw SyncError.invalidURL }
        let transport: GitUploadPackTransport
        switch scheme {
        case "https", "http":
            var username: String?, secret: String?
            if case .httpsToken(let u, let t) = remote.credential { username = u; secret = t }
            transport = HTTPSUploadPackTransport(repoURL: url, username: username, password: secret)
        case "ssh":
            // Preserve url.path verbatim (including a leading "/") so absolute server
            // paths like ssh://foo@host/some/repo stay absolute. Hosts that want a
            // home-relative path use the ~ form (ssh://host/~/repo), which is preserved too.
            transport = try makeSSH(host: url.host ?? "", port: url.port ?? 22,
                                    user: url.user ?? "git", path: url.path)
        default:
            throw SyncError.unsupportedScheme(scheme)
        }
        try await GitCloner(transport: transport).clone(ref: ref, into: destination)
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
