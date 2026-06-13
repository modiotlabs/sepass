import Foundation

/// Persists pinned SSH host keys (host → OpenSSH key line) in UserDefaults — the app's
/// equivalent of `~/.ssh/known_hosts`. Thread-safe via UserDefaults; the pinning
/// callback runs on a background NIO thread.
final class KnownHostsStore {
    private let key = "ssh.knownhosts"

    private var dict: [String: String] {
        get { (UserDefaults.standard.dictionary(forKey: key) as? [String: String]) ?? [:] }
        set { UserDefaults.standard.set(newValue, forKey: key) }
    }

    func line(for host: String) -> String? { dict[host] }

    func record(host: String, line: String) {
        var d = dict; d[host] = line; dict = d
    }

    func remove(host: String) {
        var d = dict; d[host] = nil; dict = d
    }

    func removeAll() { UserDefaults.standard.removeObject(forKey: key) }

    /// Sorted (host, line) pairs for display.
    func all() -> [(host: String, line: String)] {
        dict.sorted { $0.key < $1.key }.map { (host: $0.key, line: $0.value) }
    }
}
