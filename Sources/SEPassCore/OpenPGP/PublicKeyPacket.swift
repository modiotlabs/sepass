import Foundation
import CryptoKit

/// Builds and fingerprints v4 OpenPGP public-key packet bodies for our P-256 keys.
/// Shared by the primary (ECDSA) and encryption subkey (ECDH).
enum PublicKeyPacket {

    /// Body of a v4 ECDSA public-key packet (algorithm 19) for the given SEC1 point.
    static func ecdsaBody(point: [UInt8], creationTime: UInt32) -> [UInt8] {
        var body: [UInt8] = [0x04]                       // version 4
        body += creationTime.be4
        body += [PublicKeyAlgorithm.ecdsa.rawValue]
        body += [UInt8(Curve.p256OID.count)] + Curve.p256OID
        body += MPI.encode(point)
        return body
    }

    /// Body of a v4 ECDH public-key packet (algorithm 18), including the KDF params
    /// that tell a sender which hash + symmetric algorithm to use for key wrapping.
    static func ecdhBody(point: [UInt8], creationTime: UInt32,
                         kdfHash: HashAlgorithm, kdfSymmetric: SymmetricAlgorithm) -> [UInt8] {
        var body: [UInt8] = [0x04]
        body += creationTime.be4
        body += [PublicKeyAlgorithm.ecdh.rawValue]
        body += [UInt8(Curve.p256OID.count)] + Curve.p256OID
        body += MPI.encode(point)
        // KDF params: size(3), reserved(1), hash ID, symmetric ID.
        body += [0x03, 0x01, kdfHash.rawValue, kdfSymmetric.rawValue]
        return body
    }

    /// v4 fingerprint: SHA-1 over 0x99 ‖ uint16(len) ‖ public-key packet body
    /// (RFC 4880 §12.2). Key ID is the low 8 bytes.
    static func fingerprint(body: [UInt8]) -> [UInt8] {
        let preimage: [UInt8] = [0x99] + body.count.be2 + body
        var sha1 = Insecure.SHA1()
        sha1.update(data: Data(preimage))
        return Array(sha1.finalize())
    }

    static func keyID(fromFingerprint fpr: [UInt8]) -> [UInt8] {
        Array(fpr.suffix(8))
    }

    /// The "hashed key material" prefix used when a signature covers a key:
    /// 0x99 ‖ uint16(len) ‖ body (RFC 4880 §5.2.4).
    static func signedKeyData(body: [UInt8]) -> [UInt8] {
        [0x99] + body.count.be2 + body
    }
}
