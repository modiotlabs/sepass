import Foundation
import CryptoKit

/// Encodes an `ecdsa-sha2-nistp256` public key in OpenSSH "authorized_keys" format so
/// the user can paste it as a deploy key. Works from the 65-byte SEC1 point of the
/// (Secure Enclave) P-256 key.
public enum OpenSSHKey {
    /// SSH wire string: 4-byte big-endian length prefix + bytes.
    private static func sshString(_ bytes: [UInt8]) -> [UInt8] {
        UInt32(bytes.count).be4 + bytes
    }

    /// The binary public-key blob (the value that is base64'd in an OpenSSH line and
    /// also what host-key fingerprints are computed over).
    public static func ecdsaP256Blob(point: [UInt8]) -> [UInt8] {
        sshString(Array("ecdsa-sha2-nistp256".utf8))
            + sshString(Array("nistp256".utf8))
            + sshString(point) // 0x04 ‖ X ‖ Y
    }

    /// Full one-line OpenSSH public key, e.g. "ecdsa-sha2-nistp256 AAAA… comment".
    public static func authorizedKey(point: [UInt8], comment: String = "sepass") -> String {
        let blob = ecdsaP256Blob(point: point)
        return "ecdsa-sha2-nistp256 \(Data(blob).base64EncodedString()) \(comment)"
    }

    /// OpenSSH-style SHA-256 fingerprint of a key blob, e.g. "SHA256:abc…" (no padding),
    /// used to show the user which host key was pinned.
    public static func sha256Fingerprint(ofBlob blob: [UInt8]) -> String {
        let digest = SHA256.hash(data: Data(blob))
        let b64 = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(b64)"
    }
}
