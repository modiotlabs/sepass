import Foundation

/// OpenPGP packet tags (RFC 4880 §4.3). Only the ones SE Pass touches are listed.
enum PacketTag: UInt8 {
    case pkesk = 1            // Public-Key Encrypted Session Key
    case signature = 2
    case secretKey = 5
    case publicKey = 6
    case secretSubkey = 7
    case compressed = 8
    case symEncrypted = 9     // Symmetrically Encrypted Data (legacy, no MDC)
    case literal = 11
    case userID = 13
    case publicSubkey = 14
    case symEncryptedIntegrity = 18  // Sym. Encrypted and Integrity Protected Data
}

/// Public-key algorithm IDs (RFC 4880 §9.1, RFC 6637).
enum PublicKeyAlgorithm: UInt8 {
    case rsaEncryptSign = 1
    case ecdh = 18
    case ecdsa = 19
    case eddsa = 22
}

/// Symmetric cipher IDs (RFC 4880 §9.2). SE Pass needs to *decrypt* whatever a
/// peer chose, so several are listed even though we prefer AES-256 when exporting.
public enum SymmetricAlgorithm: UInt8, Sendable {
    case aes128 = 7
    case aes192 = 8
    case aes256 = 9

    var keySize: Int {
        switch self {
        case .aes128: return 16
        case .aes192: return 24
        case .aes256: return 32
        }
    }

    var blockSize: Int { 16 }
}

/// Hash algorithm IDs (RFC 4880 §9.4).
public enum HashAlgorithm: UInt8, Sendable {
    case sha256 = 8
    case sha384 = 9
    case sha512 = 10
}

/// Compression algorithm IDs (RFC 4880 §9.3).
enum CompressionAlgorithm: UInt8 {
    case uncompressed = 0
    case zip = 1     // raw DEFLATE (RFC 1951)
    case zlib = 2    // zlib (RFC 1950)
    case bzip2 = 3
}

enum SignatureType: UInt8 {
    case positiveCertification = 0x13
    case subkeyBinding = 0x18
}

/// Signature subpacket types (RFC 4880 §5.2.3.1) used when self-signing.
enum SignatureSubpacket: UInt8 {
    case creationTime = 2
    case issuer = 16
    case keyFlags = 27
    case preferredSymmetric = 11
    case preferredHash = 21
    case preferredCompression = 22
    case features = 30
    case issuerFingerprint = 33
}

/// Key-flag bits (RFC 4880 §5.2.3.21).
struct KeyFlags {
    static let certify: UInt8 = 0x01
    static let sign: UInt8 = 0x02
    static let encryptComms: UInt8 = 0x04
    static let encryptStorage: UInt8 = 0x08
}

/// ECC curve OIDs (RFC 6637 §11). SE Pass only ever uses NIST P-256, which is the
/// sole curve the Secure Enclave supports.
enum Curve {
    /// 1.2.840.10045.3.1.7 — NIST P-256 / secp256r1, encoded as an OpenPGP curve OID
    /// (one length byte followed by the DER OID body, with no tag/length prefix).
    static let p256OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
}
