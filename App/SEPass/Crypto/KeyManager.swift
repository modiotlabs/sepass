import Foundation
import CryptoKit
import LocalAuthentication
import SEPassCore

/// Persisted, non-secret description of the generated key, cached so the app can show
/// the public key and decrypt without re-running (or biometric-prompting for) the
/// signing key on every launch.
struct StoredKeyInfo: Codable {
    var armoredPublicKey: String
    var primaryFingerprintHex: String
    var subkeyFingerprintHex: String
    var subkeyKeyIDHex: String
    var kdfHash: UInt8
    var kdfSymmetric: UInt8
    var creationTime: UInt32
    var userID: String

    var recipient: RecipientKey {
        RecipientKey(fingerprint: Hex.bytes(subkeyFingerprintHex),
                     keyID: Hex.bytes(subkeyKeyIDHex),
                     kdfHash: HashAlgorithm(rawValue: kdfHash) ?? .sha256,
                     kdfSymmetric: SymmetricAlgorithm(rawValue: kdfSymmetric) ?? .aes256)
    }
}

enum Hex {
    static func bytes(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
            if let b = UInt8(s[i..<j], radix: 16) { out.append(b) }
            i = j
        }
        return out
    }
}

/// Owns the device keypair lifecycle: generation, persistence, public-key export, and
/// building a biometric-gated decryptor. Hides the Secure-Enclave-vs-software split.
final class KeyManager {
    private let signingAccount = "se-signing-key"
    private let agreementAccount = "se-agreement-key"
    private let infoURL: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        infoURL = support.appendingPathComponent("keyinfo.json")
    }

    var storedInfo: StoredKeyInfo? {
        guard let data = try? Data(contentsOf: infoURL) else { return nil }
        return try? JSONDecoder().decode(StoredKeyInfo.self, from: data)
    }

    var hasKey: Bool { storedInfo != nil }

    /// Generate a fresh keypair, persist it, and return the exported public key. The
    /// creation time is supplied by the caller so the result is reproducible/testable.
    func generate(userID: String, creationTime: UInt32) throws -> StoredKeyInfo {
        let signer: PGPSigner
        let agreement: PGPKeyAgreement

        #if targetEnvironment(simulator)
        // No Secure Enclave in the simulator: use software keys so the app runs. The
        // signing key is only needed during this call (the public key is cached
        // afterwards), so only the agreement key is persisted.
        let swSign = SoftwareP256Signer()
        let swAgree = SoftwareP256KeyAgreement()
        try Keychain.set(swAgree.rawRepresentation, account: agreementAccount)
        signer = swSign; agreement = swAgree
        #else
        let seSign = try SecureEnclaveFactory.makeSigningKey()
        let seAgree = try SecureEnclaveFactory.makeAgreementKey()
        try Keychain.set(seSign.dataRepresentation, account: signingAccount)
        try Keychain.set(seAgree.dataRepresentation, account: agreementAccount)
        signer = SecureEnclaveSigner(key: seSign)
        agreement = SecureEnclaveKeyAgreement(key: seAgree)
        #endif

        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement, userID: userID, creationTime: creationTime)
        let info = StoredKeyInfo(
            armoredPublicKey: material.armoredPublicKey,
            primaryFingerprintHex: material.primaryFingerprint.map { String(format: "%02x", $0) }.joined(),
            subkeyFingerprintHex: material.recipient.fingerprint.map { String(format: "%02x", $0) }.joined(),
            subkeyKeyIDHex: material.recipient.keyID.map { String(format: "%02x", $0) }.joined(),
            kdfHash: material.recipient.kdfHash.rawValue,
            kdfSymmetric: material.recipient.kdfSymmetric.rawValue,
            creationTime: creationTime, userID: userID)
        try JSONEncoder().encode(info).write(to: infoURL, options: .completeFileProtection)
        return info
    }

    func deleteKey() {
        Keychain.delete(account: signingAccount)
        Keychain.delete(account: agreementAccount)
        try? FileManager.default.removeItem(at: infoURL)
    }

    /// Build a decryptor backed by the agreement key. On device this loads the Enclave
    /// key with an LAContext so the ECDH step prompts for biometrics.
    func makeDecryptor(reason: String) throws -> PGPDecryptor {
        guard let info = storedInfo, let blob = Keychain.get(account: agreementAccount) else {
            throw KeyError.noKey
        }
        let agreement: PGPKeyAgreement
        #if targetEnvironment(simulator)
        agreement = try SoftwareP256KeyAgreement(rawRepresentation: blob)
        #else
        let context = LAContext()
        context.localizedReason = reason
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
        agreement = SecureEnclaveKeyAgreement(key: key)
        #endif
        return PGPDecryptor(agreement: agreement, recipient: info.recipient)
    }

    enum KeyError: Error { case noKey }
}
