import Foundation
import CryptoKit

/// The RFC 6637 §7 key-derivation function that turns an ECDH shared secret into the
/// key-encryption key (KEK) used to unwrap the OpenPGP session key.
enum RFC6637KDF {

    /// - sharedX: the ECDH shared secret (X coordinate), as produced by the Secure
    ///   Enclave / software key-agreement provider.
    /// - fingerprint: the 20-byte v4 fingerprint of the recipient encryption subkey.
    /// Returns a KEK whose length matches the KDF symmetric algorithm's key size.
    static func deriveKEK(sharedX: [UInt8],
                          fingerprint: [UInt8],
                          kdfHash: HashAlgorithm,
                          kdfSymmetric: SymmetricAlgorithm) throws -> [UInt8] {
        // Param = curveOID(len-prefixed) || pkAlg(18) || 0x03 0x01 hashID symID ||
        //         "Anonymous Sender    " (20) || recipient fingerprint (20).
        var param: [UInt8] = []
        param += [UInt8(Curve.p256OID.count)] + Curve.p256OID
        param += [PublicKeyAlgorithm.ecdh.rawValue]
        param += [0x03, 0x01, kdfHash.rawValue, kdfSymmetric.rawValue]
        param += Array("Anonymous Sender    ".utf8) // exactly 20 octets
        param += fingerprint

        // m = 0x00000001 (counter) || sharedX || Param, hashed by the KDF hash.
        let preimage: [UInt8] = [0x00, 0x00, 0x00, 0x01] + sharedX + param
        let digest = hash(preimage, with: kdfHash)
        return Array(digest.prefix(kdfSymmetric.keySize))
    }

    private static func hash(_ bytes: [UInt8], with algorithm: HashAlgorithm) -> [UInt8] {
        switch algorithm {
        case .sha256: return Array(SHA256.hash(data: Data(bytes)))
        case .sha384: return Array(SHA384.hash(data: Data(bytes)))
        case .sha512: return Array(SHA512.hash(data: Data(bytes)))
        }
    }
}
