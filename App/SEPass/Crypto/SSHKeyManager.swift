import Foundation
import CryptoKit
import SEPassCore

/// Manages the dedicated SSH authentication key. Like the decryption key it's
/// Secure-Enclave-backed (private half never leaves the device), but it's a separate
/// key used only to authenticate to the git host — and it is NOT biometric-gated, so
/// cloning doesn't prompt for Face ID. The user adds its public key as a deploy key.
final class SSHKeyManager {
    private let account = "se-ssh-key"

    var hasKey: Bool { Keychain.get(account: account) != nil }

    private static let keyComment = "sepass"

    /// The OpenSSH public-key line, derived on demand from the stored key.
    var publicKeyOpenSSH: String? {
        guard let point = publicKeyPoint() else { return nil }
        return OpenSSHKey.authorizedKey(point: point, comment: Self.keyComment)
    }

    /// Generate (or replace) the SSH key and return its OpenSSH public line.
    @discardableResult
    func generate() throws -> String {
        let point: [UInt8]
        #if targetEnvironment(simulator)
        let sw = P256.Signing.PrivateKey()
        try Keychain.set(sw.rawRepresentation, account: account)
        point = [UInt8](sw.publicKey.x963Representation)
        #else
        let access = try SecureEnclaveFactory.accessControl(requireBiometry: false)
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        try Keychain.set(key.dataRepresentation, account: account)
        point = [UInt8](key.publicKey.x963Representation)
        #endif
        return OpenSSHKey.authorizedKey(point: point, comment: Self.keyComment)
    }

    func deleteKey() {
        Keychain.delete(account: account)
    }

    /// Build an SSH transport authenticated by this key, with host-key pinning.
    func makeTransport(host: String, port: Int, username: String, repoPath: String,
                       hostKeyPolicy: SSHHostKeyPolicy) throws -> GitUploadPackTransport {
        guard let blob = Keychain.get(account: account) else { throw SyncError.sshNoKey }
        #if targetEnvironment(simulator)
        let sw = try P256.Signing.PrivateKey(rawRepresentation: blob)
        return SSHUploadPackTransport(host: host, port: port, username: username, repoPath: repoPath,
                                      softwareKey: sw, hostKeyPolicy: hostKeyPolicy)
        #else
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        return SSHUploadPackTransport(host: host, port: port, username: username, repoPath: repoPath,
                                      secureEnclaveKey: key, hostKeyPolicy: hostKeyPolicy)
        #endif
    }

    private func publicKeyPoint() -> [UInt8]? {
        guard let blob = Keychain.get(account: account) else { return nil }
        #if targetEnvironment(simulator)
        guard let key = try? P256.Signing.PrivateKey(rawRepresentation: blob) else { return nil }
        return [UInt8](key.publicKey.x963Representation)
        #else
        guard let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob) else { return nil }
        return [UInt8](key.publicKey.x963Representation)
        #endif
    }
}
