import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// `git-upload-pack` over smart HTTP (RFC-less; see git's http-protocol.txt). Uses
/// URLSession, so the OS handles TLS, proxies, and (optionally) certificate pinning —
/// no native git/SSL dependency. Covers public repos and HTTPS token/basic auth.
public struct HTTPSUploadPackTransport: GitUploadPackTransport {
    private let repoURL: URL
    private let username: String?
    private let password: String?
    private let session: URLSession

    /// - repoURL: the clone URL, e.g. https://host/user/store.git
    /// - username/password: optional HTTP Basic credentials (for a token, use the
    ///   token as the password and any non-empty username the host accepts).
    public init(repoURL: URL, username: String? = nil, password: String? = nil,
                session: URLSession = .shared) {
        self.repoURL = repoURL
        self.username = username
        self.password = password
        self.session = session
    }

    public func advertiseRefs() async throws -> [UInt8] {
        var url = repoURL
        url.appendPathComponent("info/refs")
        var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        comps.queryItems = [URLQueryItem(name: "service", value: "git-upload-pack")]
        var request = URLRequest(url: comps.url!)
        request.httpMethod = "GET"
        request.setValue("application/x-git-upload-pack-advertisement", forHTTPHeaderField: "Accept")
        applyAuth(&request)
        return try await send(request)
    }

    public func fetchPack(_ requestBody: [UInt8]) async throws -> [UInt8] {
        var url = repoURL
        url.appendPathComponent("git-upload-pack")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-git-upload-pack-request", forHTTPHeaderField: "Content-Type")
        request.setValue("application/x-git-upload-pack-result", forHTTPHeaderField: "Accept")
        request.httpBody = Data(requestBody)
        applyAuth(&request)
        return try await send(request)
    }

    private func applyAuth(_ request: inout URLRequest) {
        guard let username, let password else { return }
        let token = Data("\(username):\(password)".utf8).base64EncodedString()
        request.setValue("Basic \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("git/sepass", forHTTPHeaderField: "User-Agent")
    }

    private func send(_ request: URLRequest) async throws -> [UInt8] {
        var request = request
        // Never serve git smart-HTTP responses from cache — refs change, and a stale
        // advertisement could mask auth/visibility changes.
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = 30   // don't hang forever on a stalled host
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw GitError.transport(error.localizedDescription)
        }
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            let reason = http.statusCode == 401 || http.statusCode == 403
                ? "authentication required or failed" : "HTTP \(http.statusCode)"
            throw GitError.transport(reason)
        }
        return [UInt8](data)
    }
}
