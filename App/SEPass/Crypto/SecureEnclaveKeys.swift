import Foundation
import CryptoKit
import LocalAuthentication
import SEPassCore

/// Secure-Enclave-backed conformers to the SEPassCore key protocols. The private
/// keys are generated in and never leave the Enclave; only the ECDH and ECDSA
/// *operations* cross the boundary.
///
/// On the simulator (no Enclave) the app substitutes the software conformers from
/// SEPassCore — see `KeyManager`. These types are only constructed on device.
@available(iOS 16.0, *)
struct SecureEnclaveSigner: PGPSigner {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var publicKeyPoint: [UInt8] { [UInt8](key.publicKey.x963Representation) }

    func signSHA256(_ preimage: [UInt8]) throws -> [UInt8] {
        [UInt8](try key.signature(for: Data(preimage)).rawRepresentation)
    }
}

@available(iOS 16.0, *)
struct SecureEnclaveKeyAgreement: PGPKeyAgreement {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    var publicKeyPoint: [UInt8] { [UInt8](key.publicKey.x963Representation) }

    func sharedSecretX(ephemeralPoint: [UInt8]) throws -> [UInt8] {
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Data(ephemeralPoint))
        // This call performs the ECDH inside the Enclave; if the key was created with
        // a biometric access control, it prompts for Face ID / Touch ID here.
        let secret = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        return secret.withUnsafeBytes { Array($0) }
    }
}

/// Factory for Secure Enclave keys with the access control SE Pass wants: usable only
/// while unlocked, on this device, and (for the decryption key) gated behind biometric
/// authentication.
@available(iOS 16.0, *)
enum SecureEnclaveFactory {
    static func accessControl(requireBiometry: Bool) throws -> SecAccessControl {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireBiometry { flags.insert(.biometryCurrentSet) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return access
    }

    static func makeSigningKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl(requireBiometry: false))
    }

    static func makeAgreementKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl(requireBiometry: true))
    }
}
