import Foundation
import CryptoKit
import NIOCore
import NIOSSH

/// Reads the wire identity of a server host key from a `NIOSSHPublicKey`.
///
/// swift-nio-ssh doesn't expose host-key bytes publicly, but its internal storage wraps
/// a CryptoKit public key, which reflection can reach. We reconstruct the standard
/// OpenSSH key blob so the SHA-256 fingerprint matches `ssh-keygen`/`ssh-keyscan`
/// exactly — making LAN host keys verifiable out of band. If a future library version
/// changes the internal shape, `describe` returns nil and the policy degrades safely.
enum HostKeyInspector {
    static func describe(_ key: NIOSSHPublicKey) -> (line: String, fingerprint: String)? {
        guard let backing = Mirror(reflecting: key).children.first(where: { $0.label == "backingKey" })?.value,
              let assoc = Mirror(reflecting: backing).children.first?.value else { return nil }

        let type: String, blob: [UInt8]
        if let k = assoc as? P256.Signing.PublicKey {
            type = "ecdsa-sha2-nistp256"; blob = ecdsaBlob("nistp256", [UInt8](k.x963Representation))
        } else if let k = assoc as? P384.Signing.PublicKey {
            type = "ecdsa-sha2-nistp384"; blob = ecdsaBlob("nistp384", [UInt8](k.x963Representation))
        } else if let k = assoc as? P521.Signing.PublicKey {
            type = "ecdsa-sha2-nistp521"; blob = ecdsaBlob("nistp521", [UInt8](k.x963Representation))
        } else if let k = assoc as? Curve25519.Signing.PublicKey {
            type = "ssh-ed25519"
            blob = sshString(Array("ssh-ed25519".utf8)) + sshString([UInt8](k.rawRepresentation))
        } else {
            return nil
        }
        return ("\(type) \(Data(blob).base64EncodedString())", OpenSSHKey.sha256Fingerprint(ofBlob: blob))
    }

    private static func sshString(_ b: [UInt8]) -> [UInt8] { UInt32(b.count).be4 + b }
    private static func ecdsaBlob(_ curve: String, _ point: [UInt8]) -> [UInt8] {
        sshString(Array("ecdsa-sha2-\(curve)".utf8)) + sshString(Array(curve.utf8)) + sshString(point)
    }
}

/// Trust-on-first-use host-key policy, supplied by the app. `knownLine` returns the
/// pinned OpenSSH host-key line for a host (if any); `onPin` records a newly-seen host.
public struct SSHHostKeyPolicy: Sendable {
    public var knownLine: @Sendable (_ host: String) -> String?
    public var onPin: @Sendable (_ host: String, _ line: String) -> Void

    public init(knownLine: @escaping @Sendable (String) -> String?,
                onPin: @escaping @Sendable (String, String) -> Void) {
        self.knownLine = knownLine
        self.onPin = onPin
    }
}

/// `NIOSSHClientServerAuthenticationDelegate` implementing TOFU: pin on first sight,
/// verify by equality after, reject on change.
final class TOFUHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    private let host: String
    private let policy: SSHHostKeyPolicy

    init(host: String, policy: SSHHostKeyPolicy) {
        self.host = host
        self.policy = policy
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        guard let presented = HostKeyInspector.describe(hostKey) else {
            // Shouldn't happen, but never break cloning over an introspection failure.
            validationCompletePromise.succeed(())
            return
        }
        if let knownLine = policy.knownLine(host) {
            // Robust public-API comparison: rebuild the pinned key and check equality.
            if let expected = try? NIOSSHPublicKey(openSSHPublicKey: knownLine), expected == hostKey {
                validationCompletePromise.succeed(())
            } else {
                let pinned = OpenSSHKey.sha256Fingerprint(ofOpenSSHLine: knownLine) ?? "unknown"
                validationCompletePromise.fail(GitError.hostKeyRejected(
                    "Host key for \(host) changed. Pinned \(pinned), server offered \(presented.fingerprint). "
                    + "If this is a legitimate key change, remove the pin in Known Hosts and clone again."))
            }
        } else {
            policy.onPin(host, presented.line)   // first use → trust and remember
            validationCompletePromise.succeed(())
        }
    }
}
