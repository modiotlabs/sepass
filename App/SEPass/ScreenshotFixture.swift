#if DEBUG
import Foundation

/// Sample data for App Store screenshots.
///
/// This is compiled **only into DEBUG builds** and only does anything when the app is
/// launched with `SEPASS_SCREENSHOTS=1` in its environment (set by the screenshot
/// tooling — see `Tools/screenshots.sh`). It can therefore never reach a release build,
/// the App Store, or a real user.
///
/// What it does: seeds a realistic password tree on disk (so the *real* `PassStore`,
/// `BrowseView`, search and navigation render it) and supplies canned plaintext for the
/// entry-detail screen, since the simulator can't decrypt against a real store. The Key
/// screen still uses a genuine (software, simulator-only) key — no faking there.
enum ScreenshotFixture {
    /// Master switch — only true when launched by the screenshot tooling.
    static var isActive: Bool { ProcessInfo.processInfo.environment["SEPASS_SCREENSHOTS"] == "1" }

    /// Which screen to open on launch: "tree" (default), "entry", "sync", or "key".
    static var screen: String { ProcessInfo.processInfo.environment["SEPASS_SCREEN"] ?? "tree" }

    /// The identity baked into the sample key shown on the Key screen.
    static let userID = "Claire Engle <claire@fastmail.com>"

    /// Sample remote shown pre-configured on the Sync screen.
    static let sampleURL = "https://github.com/claire/password-store.git"

    /// SSH-form sample remote, for the "before the SSH key is generated" Sync screen.
    static let sampleSSHURL = "git@github.com:claire/password-store.git"

    /// AuthKind.ssh.rawValue — selects the SSH section on the Sync screen.
    static let sshAuthMode = "SSH (Enclave key)"

    /// The entry opened (and "decrypted") on the entry-detail screenshot.
    static let featuredEntryID = "Email/fastmail.com"

    /// A realistic pass tree. Folders are implied by the paths; each leaf becomes an empty
    /// `*.gpg` file so the real `PassStore` loads a genuine tree.
    static let tree: [String] = [
        "Banking/chase.com",
        "Banking/wise.com",
        "Banking/vanguard.com",
        "Email/fastmail.com",
        "Email/proton.me",
        "Servers/web01.modiot.com",
        "Servers/db-primary",
        "Servers/backup-nas",
        "Shopping/amazon.com",
        "Shopping/etsy.com",
        "Social/github.com",
        "Social/news.ycombinator.com",
        "Social/mastodon.social",
        "Wi-Fi/home",
        "Wi-Fi/office",
    ]

    /// Canned plaintext shown instead of real decryption, keyed by node id. First line is
    /// the password; the rest are pass-style fields.
    static let secrets: [String: String] = [
        "Email/fastmail.com": """
        b9$Kx2vQ7m-hZ4pLn!Wd
        login: claire@fastmail.com
        url: https://www.fastmail.com/login/
        otpauth: in authenticator app
        recovery: stored in safe deposit box
        """,
    ]

    /// Plaintext for an arbitrary node (falls back to a believable generated secret).
    static func plaintext(for node: PassNode) -> String {
        if let canned = secrets[node.id] { return canned }
        return """
        \(pseudoPassword(for: node.name))
        login: claire@example.com
        url: https://\(node.name)/
        """
    }

    /// Write the sample tree into the store directory as empty `.gpg` files.
    static func seed(into root: URL) {
        let fm = FileManager.default
        try? fm.removeItem(at: root)
        for entry in tree {
            let file = root.appendingPathComponent(entry + ".gpg")
            try? fm.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            fm.createFile(atPath: file.path, contents: Data())
        }
    }

    /// Deterministic, no-RNG faux password so screenshots are reproducible.
    private static func pseudoPassword(for name: String) -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%-")
        var value = ""
        var seed = name.unicodeScalars.reduce(2166136261) { ($0 ^ $1.value) &* 16777619 }
        for _ in 0..<18 {
            seed = seed &* 1103515245 &+ 12345
            value.append(alphabet[Int((seed >> 16) % UInt32(alphabet.count))])
        }
        return value
    }
}
#endif
