import Foundation
import SwiftUI
import SEPassCore

/// App-wide state: the device key, the synced store location, the remote config, and
/// the loaded password tree. Views observe this.
@MainActor
final class AppModel: ObservableObject {
    @Published var keyInfo: StoredKeyInfo?
    @Published var keyError: String?          // Key-tab feedback; never shown on Sync
    @Published var nodes: [PassNode] = []
    @Published var remote: GitRemote
    @Published var status: String?
    @Published var statusIsError = false
    @Published var isBusy = false

    let keyManager = KeyManager()
    let sshKeys = SSHKeyManager()
    private let git: GitService

    /// Whether a store has been cloned/imported (drives the Sync button label).
    var hasStore: Bool { !nodes.isEmpty }

    /// Cloned working tree lives in Application Support/store.
    let storeURL: URL = {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appendingPathComponent("store", isDirectory: true)
    }()

    private let remoteDefaultsKey = "git.remote"

    init() {
        // Build the git service, teaching it to make an SSH transport from the
        // Secure-Enclave SSH key when an ssh:// or git@host:path URL is used.
        let ssh = sshKeys
        var service = PureGitService()
        service.sshTransportFactory = { host, port, user, path in
            try ssh.makeTransport(host: host, port: port, username: user, repoPath: path)
        }
        git = service

        if let data = UserDefaults.standard.data(forKey: remoteDefaultsKey),
           let saved = try? JSONDecoder().decode(GitRemote.self, from: data) {
            remote = saved
        } else {
            remote = GitRemote(url: "")
        }
        keyInfo = keyManager.storedInfo
        reloadTree()
    }

    // MARK: - SSH key

    func generateSSHKey() {
        run {
            _ = try self.sshKeys.generate()
            self.status = "SSH key generated. Add it as a deploy key."
            self.objectWillChange.send()
        }
    }

    // MARK: - Key

    func generateKey(userID: String) {
        do {
            // Creation time is "now" truncated to seconds; stable thereafter via cache.
            let now = UInt32(Date().timeIntervalSince1970)
            keyInfo = try keyManager.generate(userID: userID, creationTime: now)
            keyError = nil
        } catch {
            keyError = error.localizedDescription
        }
    }

    func deleteKey() {
        keyManager.deleteKey()
        keyInfo = nil
        keyError = nil
    }

    /// Wipe everything — Enclave keys (GPG + SSH), the cloned store, and saved settings —
    /// resetting SE Pass to its first-launch state. Used for testing and as a hard reset.
    func eraseAll() {
        keyManager.deleteKey()
        sshKeys.deleteKey()
        try? FileManager.default.removeItem(at: storeURL)
        UserDefaults.standard.removeObject(forKey: remoteDefaultsKey)
        keyInfo = nil
        keyError = nil
        nodes = []
        remote = GitRemote(url: "")
        status = nil          // clear any stale sync status too
        statusIsError = false
    }

    // MARK: - Sync

    func saveRemote(_ newRemote: GitRemote) {
        remote = newRemote
        if let data = try? JSONEncoder().encode(newRemote) {
            UserDefaults.standard.set(data, forKey: remoteDefaultsKey)
        }
    }

    func clone() {
        runAsync {
            // Clone into a temp dir and only swap it in on success, so a failed clone
            // (e.g. wrong/missing credentials) never destroys the existing store.
            let temp = self.storeURL.deletingLastPathComponent().appendingPathComponent(".store-clone")
            try? FileManager.default.removeItem(at: temp)
            try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
            try await self.git.clone(self.remote, into: temp)
            await MainActor.run {
                try? FileManager.default.removeItem(at: self.storeURL)
                try? FileManager.default.moveItem(at: temp, to: self.storeURL)
                self.reloadTree()
                let count = PassStore.allEntries(self.nodes).count
                self.status = "Cloned \(count) password\(count == 1 ? "" : "s")."
            }
        }
    }

    /// Import an already-cloned store from a local folder (e.g. picked via Files). Works
    /// today without the git transport and is handy for `file://`/local repos.
    func importLocalStore(from url: URL) {
        run {
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            try? FileManager.default.removeItem(at: self.storeURL)
            try FileManager.default.copyItem(at: url, to: self.storeURL)
            self.reloadTree()
            self.status = "Imported \(self.nodes.count) top-level items."
        }
    }

    func reloadTree() {
        guard FileManager.default.fileExists(atPath: storeURL.path) else { nodes = []; return }
        nodes = PassStore(root: storeURL).load()
    }

    // MARK: - Decrypt

    func decrypt(_ node: PassNode) async throws -> String {
        let decryptor = try keyManager.makeDecryptor(reason: "Decrypt \(node.name)")
        let ciphertext = try Data(contentsOf: node.url)
        let plaintext = try decryptor.decrypt(ciphertext)
        return String(data: plaintext, encoding: .utf8) ?? "<binary data>"
    }

    // MARK: - Helpers

    private func run(_ work: @escaping () throws -> Void) {
        isBusy = true; status = nil; statusIsError = false
        do { try work() } catch { status = error.localizedDescription; statusIsError = true }
        isBusy = false
    }

    private func runAsync(_ work: @escaping () async throws -> Void) {
        isBusy = true; status = nil; statusIsError = false
        Task {
            do { try await work() }
            catch { await MainActor.run { self.status = error.localizedDescription; self.statusIsError = true } }
            await MainActor.run { self.isBusy = false }
        }
    }
}
