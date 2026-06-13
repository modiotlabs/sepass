import Foundation

/// A git transport that speaks the v0 `git-upload-pack` (clone/fetch) protocol. The
/// same two operations map onto HTTPS (two requests) and SSH/local (one channel), so
/// the clone logic above it is transport-agnostic.
public protocol GitUploadPackTransport {
    /// The ref advertisement (pkt-lines). HTTP transports strip the `# service` preamble.
    func advertiseRefs() async throws -> [UInt8]
    /// Send the want/done request, return the server's response (NAK + packfile).
    func fetchPack(_ requestBody: [UInt8]) async throws -> [UInt8]
}

/// Clone-only git client built on a `GitUploadPackTransport`.
public struct GitCloner {
    private let transport: GitUploadPackTransport
    public init(transport: GitUploadPackTransport) { self.transport = transport }

    /// Clone `ref` (a branch name, full ref, or nil for the remote's default branch)
    /// into `directory`, writing the working tree. Returns the cloned commit id.
    @discardableResult
    public func clone(ref: String?, into directory: URL) async throws -> String {
        let advertisement = try await transport.advertiseRefs()
        let (refs, head, capabilities) = try parseAdvertisement(advertisement)
        let wantSha = try pickRef(ref, refs: refs, head: head)

        let request = buildWantRequest(sha: wantSha, capabilities: capabilities)
        let response = try await transport.fetchPack(request)
        let pack = try extractPackfile(response)
        let objects = try Packfile.parse(pack)
        try GitCheckout.checkout(commitSha: wantSha, objects: objects, into: directory)
        return wantSha
    }

    // MARK: - Advertisement

    private func parseAdvertisement(_ bytes: [UInt8]) throws -> (refs: [String: String], head: String?, caps: Set<String>) {
        var refs: [String: String] = [:]
        var head: String?
        var caps: Set<String> = []
        for line in try PktLine.parse(bytes) {
            guard case .data(let payload) = line else { continue }
            var text = String(decoding: payload, as: UTF8.self)
            if text.hasPrefix("#") { continue }                  // "# service=..." preamble
            text = text.trimmingCharacters(in: .whitespacesAndNewlines)
            // The first ref line carries capabilities after a NUL byte.
            var capPart: Substring?
            if let nul = text.firstIndex(of: "\0") {
                capPart = text[text.index(after: nul)...]
                text = String(text[..<nul])
            }
            let parts = text.split(separator: " ", maxSplits: 1)
            guard parts.count == 2 else { continue }
            refs[String(parts[1])] = String(parts[0])
            if let capPart {
                caps = Set(capPart.split(separator: " ").map(String.init))
                if let symref = caps.first(where: { $0.hasPrefix("symref=HEAD:") }) {
                    head = String(symref.dropFirst("symref=HEAD:".count))
                }
            }
        }
        return (refs, head, caps)
    }

    private func pickRef(_ ref: String?, refs: [String: String], head: String?) throws -> String {
        // Prefer the requested branch/ref…
        if let ref, !ref.isEmpty,
           let sha = refs["refs/heads/\(ref)"] ?? refs[ref] ?? refs["refs/tags/\(ref)"] {
            return sha
        }
        // …otherwise fall back to the remote's default branch (HEAD), so users don't
        // have to know whether it's "main" or "master".
        if let head, let sha = refs[head] { return sha }
        if let sha = refs["HEAD"] { return sha }
        if let any = refs.values.first { return any }
        throw GitError.refNotFound(ref ?? "default branch")
    }

    // MARK: - Want request

    private func buildWantRequest(sha: String, capabilities: Set<String>) -> [UInt8] {
        var wanted = ["agent=sepass"]
        if capabilities.contains("ofs-delta") { wanted.insert("ofs-delta", at: 0) }
        let caps = wanted.joined(separator: " ")
        var body = PktLine.encode("want \(sha) \(caps)\n")
        body += PktLine.flush
        body += PktLine.encode("done\n")
        return body
    }

    // MARK: - Response

    /// The response is one or more pkt-lines (NAK/ACK/ERR) followed by a raw packfile.
    private func extractPackfile(_ response: [UInt8]) throws -> [UInt8] {
        let signature: [UInt8] = Array("PACK".utf8)
        if let start = firstIndex(of: signature, in: response) {
            return Array(response[start...])
        }
        // No packfile: surface any server-side error line.
        for line in (try? PktLine.parse(response)) ?? [] {
            if case .data(let p) = line {
                let s = String(decoding: p, as: UTF8.self)
                if s.hasPrefix("ERR") { throw GitError.transport(String(s.dropFirst(3)).trimmingCharacters(in: .whitespaces)) }
            }
        }
        throw GitError.packError("no packfile in response")
    }

    private func firstIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for i in 0...(haystack.count - needle.count) where Array(haystack[i..<i + needle.count]) == needle {
            return i
        }
        return nil
    }
}
