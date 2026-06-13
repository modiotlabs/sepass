import Foundation
import CryptoKit

/// Software-backed P-256 keys conforming to the SE Pass key protocols.
///
/// These exist for two reasons: unit tests (so the OpenPGP pipeline can be exercised
/// and round-tripped against `gpg` on macOS, where the Secure Enclave isn't usable
/// headlessly) and the simulator DEBUG build. The shipping app uses Secure Enclave
/// conformers instead — see the iOS target. Never use these in a release build.
public struct SoftwareP256Signer: PGPSigner {
    private let privateKey: P256.Signing.PrivateKey

    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.privateKey = privateKey
    }

    public var publicKeyPoint: [UInt8] { [UInt8](privateKey.publicKey.x963Representation) }

    public func signSHA256(_ preimage: [UInt8]) throws -> [UInt8] {
        // CryptoKit hashes `preimage` with SHA-256 then signs; for P-256 this equals
        // OpenPGP's "hash, then ECDSA-sign the digest" with no truncation.
        let signature = try privateKey.signature(for: Data(preimage))
        return [UInt8](signature.rawRepresentation) // 64-byte r ‖ s
    }
}

public struct SoftwareP256KeyAgreement: PGPKeyAgreement {
    private let privateKey: P256.KeyAgreement.PrivateKey

    public init(privateKey: P256.KeyAgreement.PrivateKey = P256.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
    }

    /// Expose the raw private scalar so tests can hand the same key material to `gpg`.
    public var rawRepresentation: Data { privateKey.rawRepresentation }

    public init(rawRepresentation: Data) throws {
        self.privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation)
    }

    public var publicKeyPoint: [UInt8] { [UInt8](privateKey.publicKey.x963Representation) }

    public func sharedSecretX(ephemeralPoint: [UInt8]) throws -> [UInt8] {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Data(ephemeralPoint))
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        return secret.withUnsafeBytes { Array($0) } // 32-byte X coordinate
    }
}
