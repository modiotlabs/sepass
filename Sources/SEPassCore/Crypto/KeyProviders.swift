import Foundation

/// The two operations SE Pass needs from its P-256 keys, expressed as protocols so
/// the OpenPGP core never touches Secure Enclave APIs directly. The iOS app supplies
/// Secure-Enclave-backed conformers (private key never leaves hardware); tests and
/// the simulator DEBUG build supply software-backed ones.
///
/// Both expose the public key as a 65-byte SEC1 uncompressed point (`0x04 ‖ X ‖ Y`),
/// which is exactly what OpenPGP carries inside an MPI for NIST curves.

/// A signing key used for the OpenPGP primary key (self-certification + subkey binding).
public protocol PGPSigner {
    /// 65-byte uncompressed SEC1 point of the public key.
    var publicKeyPoint: [UInt8] { get }

    /// ECDSA-sign `preimage` over SHA-256, returning a fixed 64-byte `r ‖ s`.
    ///
    /// The caller passes the full byte stream OpenPGP hashes (not a digest); the
    /// implementation hashes with SHA-256 internally. For P-256 + SHA-256 there is no
    /// hash truncation, so this matches OpenPGP's ECDSA exactly.
    func signSHA256(_ preimage: [UInt8]) throws -> [UInt8]
}

/// A key-agreement key used for the OpenPGP encryption subkey (the only key touched
/// during decryption).
public protocol PGPKeyAgreement {
    /// 65-byte uncompressed SEC1 point of the public key.
    var publicKeyPoint: [UInt8] { get }

    /// ECDH with the sender's ephemeral public point (65-byte SEC1), returning the
    /// 32-byte shared X coordinate — the input to the RFC 6637 KDF. In the app this
    /// is the single operation performed inside the Secure Enclave.
    func sharedSecretX(ephemeralPoint: [UInt8]) throws -> [UInt8]
}
