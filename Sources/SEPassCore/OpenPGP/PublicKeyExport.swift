import Foundation

/// Identifying material for the encryption subkey, needed both to advertise the key
/// and to drive decryption (PKESK matching + the RFC 6637 KDF, which mixes in the
/// recipient subkey's fingerprint).
public struct RecipientKey: Sendable {
    public let fingerprint: [UInt8]      // 20-byte v4 fingerprint of the ECDH subkey
    public let keyID: [UInt8]            // low 8 bytes of the fingerprint
    public let kdfHash: HashAlgorithm
    public let kdfSymmetric: SymmetricAlgorithm

    public init(fingerprint: [UInt8], keyID: [UInt8], kdfHash: HashAlgorithm, kdfSymmetric: SymmetricAlgorithm) {
        self.fingerprint = fingerprint
        self.keyID = keyID
        self.kdfHash = kdfHash
        self.kdfSymmetric = kdfSymmetric
    }
}

/// The result of exporting a key: the armored public key plus the identifiers a
/// caller needs to display it and to decrypt messages sent to it.
public struct PGPKeyMaterial: Sendable {
    public let armoredPublicKey: String
    public let primaryFingerprint: [UInt8]
    public let recipient: RecipientKey
    public let creationTime: UInt32

    /// Uppercase hex of the primary fingerprint, grouped in 4-char blocks — the form
    /// users paste into `.gpg-id` / `pass init`.
    public var primaryFingerprintHex: String { Self.formatFingerprint(primaryFingerprint) }
    public var subkeyFingerprintHex: String { Self.formatFingerprint(recipient.fingerprint) }

    static func formatFingerprint(_ fpr: [UInt8]) -> String {
        let hex = fpr.map { String(format: "%02X", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map {
            let s = hex.index(hex.startIndex, offsetBy: $0)
            let e = hex.index(s, offsetBy: 4, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[s..<e])
        }.joined(separator: " ")
    }
}

/// Builds a GnuPG-importable transferable public key from a Secure-Enclave (or, in
/// tests, software) signing primary + ECDH subkey.
public enum OpenPGPKeyExporter {

    public static func export(signer: PGPSigner,
                              agreement: PGPKeyAgreement,
                              userID: String,
                              creationTime: UInt32,
                              kdfHash: HashAlgorithm = .sha256,
                              kdfSymmetric: SymmetricAlgorithm = .aes256) throws -> PGPKeyMaterial {

        // --- Primary key (ECDSA, certify+sign) ---
        let primaryBody = PublicKeyPacket.ecdsaBody(point: signer.publicKeyPoint, creationTime: creationTime)
        let primaryFingerprint = PublicKeyPacket.fingerprint(body: primaryBody)
        let primaryKeyID = PublicKeyPacket.keyID(fromFingerprint: primaryFingerprint)

        // --- Encryption subkey (ECDH, encrypt) ---
        let subkeyBody = PublicKeyPacket.ecdhBody(point: agreement.publicKeyPoint, creationTime: creationTime,
                                                  kdfHash: kdfHash, kdfSymmetric: kdfSymmetric)
        let subkeyFingerprint = PublicKeyPacket.fingerprint(body: subkeyBody)
        let subkeyKeyID = PublicKeyPacket.keyID(fromFingerprint: subkeyFingerprint)

        // --- User ID ---
        let uidBytes = Array(userID.utf8)

        // --- Positive certification self-signature over (primary, UID) ---
        // UID is hashed as 0xB4 ‖ uint32(len) ‖ bytes (RFC 4880 §5.2.4).
        let uidHashData: [UInt8] = [0xB4] + UInt32(uidBytes.count).be4 + uidBytes
        let certHashed =
            SignatureBuilder.subpacket(.creationTime, creationTime.be4) +
            SignatureBuilder.subpacket(.issuerFingerprint, [0x04] + primaryFingerprint) +
            SignatureBuilder.subpacket(.keyFlags, [KeyFlags.certify | KeyFlags.sign]) +
            SignatureBuilder.subpacket(.preferredSymmetric, [SymmetricAlgorithm.aes256.rawValue,
                                                             SymmetricAlgorithm.aes192.rawValue,
                                                             SymmetricAlgorithm.aes128.rawValue]) +
            SignatureBuilder.subpacket(.preferredHash, [HashAlgorithm.sha256.rawValue,
                                                        HashAlgorithm.sha384.rawValue,
                                                        HashAlgorithm.sha512.rawValue]) +
            SignatureBuilder.subpacket(.preferredCompression, [CompressionAlgorithm.zlib.rawValue,
                                                               CompressionAlgorithm.zip.rawValue,
                                                               CompressionAlgorithm.uncompressed.rawValue]) +
            SignatureBuilder.subpacket(.features, [0x01]) // MDC
        let certUnhashed = SignatureBuilder.subpacket(.issuer, primaryKeyID) // issuer key ID
        let certSig = try SignatureBuilder.makeSignature(
            type: .positiveCertification, signer: signer,
            signedData: PublicKeyPacket.signedKeyData(body: primaryBody) + uidHashData,
            hashed: certHashed, unhashed: certUnhashed)

        // --- Subkey binding signature over (primary, subkey) ---
        let bindHashed =
            SignatureBuilder.subpacket(.creationTime, creationTime.be4) +
            SignatureBuilder.subpacket(.issuerFingerprint, [0x04] + primaryFingerprint) +
            SignatureBuilder.subpacket(.keyFlags, [KeyFlags.encryptComms | KeyFlags.encryptStorage])
        let bindUnhashed = SignatureBuilder.subpacket(.issuer, primaryKeyID)
        let bindSig = try SignatureBuilder.makeSignature(
            type: .subkeyBinding, signer: signer,
            signedData: PublicKeyPacket.signedKeyData(body: primaryBody)
                      + PublicKeyPacket.signedKeyData(body: subkeyBody),
            hashed: bindHashed, unhashed: bindUnhashed)

        // --- Assemble the transferable public key ---
        var packets: [UInt8] = []
        packets += PacketParser.serialize(tag: .publicKey, body: primaryBody)
        packets += PacketParser.serialize(tag: .userID, body: uidBytes)
        packets += PacketParser.serialize(tag: .signature, body: certSig)
        packets += PacketParser.serialize(tag: .publicSubkey, body: subkeyBody)
        packets += PacketParser.serialize(tag: .signature, body: bindSig)

        let recipient = RecipientKey(fingerprint: subkeyFingerprint, keyID: subkeyKeyID,
                                     kdfHash: kdfHash, kdfSymmetric: kdfSymmetric)
        return PGPKeyMaterial(armoredPublicKey: Armor.armorPublicKey(packets),
                              primaryFingerprint: primaryFingerprint,
                              recipient: recipient,
                              creationTime: creationTime)
    }
}
