import Foundation
import CryptoKit

/// Decrypts an OpenPGP message addressed to our P-256 ECDH subkey. The only
/// secret-key operation is the ECDH step, delegated to the injected key-agreement
/// provider (the Secure Enclave in the app); everything else is public math.
public struct PGPDecryptor {
    private let agreement: PGPKeyAgreement
    private let recipient: RecipientKey

    public init(agreement: PGPKeyAgreement, recipient: RecipientKey) {
        self.agreement = agreement
        self.recipient = recipient
    }

    /// Decrypt a binary OpenPGP message (a `pass` `.gpg` file) to its plaintext.
    public func decrypt(_ message: Data) throws -> Data {
        let packets = try PacketParser.parse([UInt8](message))

        // 1. Recover the session key from the PKESK addressed to our subkey.
        guard let pkesk = packets.first(where: { $0.tag == .pkesk }) else {
            throw OpenPGPError.malformed("no PKESK packet")
        }
        let (symAlg, sessionKey) = try recoverSessionKey(from: pkesk.body)

        // 2. Decrypt the integrity-protected (or legacy) encrypted data packet.
        let inner: [UInt8]
        if let seipd = packets.first(where: { $0.tag == .symEncryptedIntegrity }) {
            inner = try decryptSEIPD(seipd.body, symAlg: symAlg, sessionKey: sessionKey)
        } else if let sed = packets.first(where: { $0.tag == .symEncrypted }) {
            throw OpenPGPError.unsupported("legacy SED packet (no MDC) — \(sed.body.count) bytes")
        } else {
            throw OpenPGPError.malformed("no encrypted data packet")
        }

        // 3. Walk the inner packets (optionally compressed) down to the literal data.
        return try extractLiteral(from: inner)
    }

    // MARK: - Session key (RFC 6637 §8 + RFC 4880 §5.1)

    private func recoverSessionKey(from body: [UInt8]) throws -> (SymmetricAlgorithm, [UInt8]) {
        var r = ByteReader(body)
        guard try r.readByte() == 3 else { throw OpenPGPError.unsupported("PKESK version") }
        let keyID = try r.read(8)
        guard keyID == recipient.keyID || keyID.allSatisfy({ $0 == 0 }) else {
            throw OpenPGPError.noMatchingKey
        }
        guard try r.readByte() == PublicKeyAlgorithm.ecdh.rawValue else {
            throw OpenPGPError.unsupported("PKESK is not ECDH")
        }
        let ephemeralPoint = try r.readMPI()                 // 0x04 ‖ X ‖ Y
        let wrappedLen = Int(try r.readByte())
        let wrapped = try r.read(wrappedLen)

        // ECDH in the Secure Enclave / software provider → shared X coordinate.
        let sharedX = try agreement.sharedSecretX(ephemeralPoint: ephemeralPoint)
        let kek = try RFC6637KDF.deriveKEK(sharedX: sharedX,
                                           fingerprint: recipient.fingerprint,
                                           kdfHash: recipient.kdfHash,
                                           kdfSymmetric: recipient.kdfSymmetric)
        let m = try SymmetricCipher.aesKeyUnwrap(kek: kek, wrapped: wrapped)

        // m = symAlgID ‖ sessionKey ‖ checksum(2), PKCS#5-padded to 8 bytes.
        let unpadded = try stripPKCS5(m)
        guard let symAlgID = unpadded.first, let alg = SymmetricAlgorithm(rawValue: symAlgID) else {
            throw OpenPGPError.unsupported("session symmetric algorithm")
        }
        let keyLen = alg.keySize
        guard unpadded.count == 1 + keyLen + 2 else {
            throw OpenPGPError.malformed("session key length mismatch")
        }
        let sessionKey = Array(unpadded[1..<1 + keyLen])
        let checksum = Int(unpadded[1 + keyLen]) << 8 | Int(unpadded[2 + keyLen])
        let computed = sessionKey.reduce(0) { ($0 + Int($1)) } & 0xffff
        guard checksum == computed else { throw OpenPGPError.checksumMismatch }
        return (alg, sessionKey)
    }

    private func stripPKCS5(_ data: [UInt8]) throws -> [UInt8] {
        guard let pad = data.last, pad >= 1, pad <= 8, data.count >= Int(pad) else {
            throw OpenPGPError.malformed("bad PKCS5 padding")
        }
        guard data.suffix(Int(pad)).allSatisfy({ $0 == pad }) else {
            throw OpenPGPError.malformed("inconsistent PKCS5 padding")
        }
        return Array(data.dropLast(Int(pad)))
    }

    // MARK: - SEIPD (RFC 4880 §5.13)

    private func decryptSEIPD(_ body: [UInt8], symAlg: SymmetricAlgorithm, sessionKey: [UInt8]) throws -> [UInt8] {
        guard symAlg == .aes128 || symAlg == .aes192 || symAlg == .aes256 else {
            throw OpenPGPError.unsupported("non-AES session cipher")
        }
        guard body.first == 1 else { throw OpenPGPError.unsupported("SEIPD version") }
        let ciphertext = Array(body.dropFirst())
        let decrypted = try SymmetricCipher.cfbDecrypt(key: sessionKey, ciphertext: ciphertext)

        let bs = symAlg.blockSize
        guard decrypted.count >= bs + 2 + 22 else { throw OpenPGPError.malformed("SEIPD too short") }
        // Quick-check: the last two bytes of the random prefix are repeated.
        guard decrypted[bs - 2] == decrypted[bs] && decrypted[bs - 1] == decrypted[bs + 1] else {
            throw OpenPGPError.malformed("SEIPD prefix quick-check failed")
        }

        // Trailing MDC packet: 0xD3 0x14 ‖ SHA-1(everything hashed so far).
        let mdcStart = decrypted.count - 22
        let mdcHeader = Array(decrypted[mdcStart..<mdcStart + 2])
        guard mdcHeader == [0xD3, 0x14] else { throw OpenPGPError.malformed("missing MDC packet") }
        let hashedRegion = Array(decrypted[0..<decrypted.count - 20]) // includes 0xD3 0x14
        let expected = Array(decrypted[decrypted.count - 20..<decrypted.count])
        var sha1 = Insecure.SHA1()
        sha1.update(data: Data(hashedRegion))
        guard Array(sha1.finalize()) == expected else { throw OpenPGPError.mdcMismatch }

        // Strip the random prefix and the whole 22-byte MDC packet.
        return Array(decrypted[(bs + 2)..<mdcStart])
    }

    // MARK: - Literal extraction

    private func extractLiteral(from packetBytes: [UInt8]) throws -> Data {
        let packets = try PacketParser.parse(packetBytes)
        for packet in packets {
            switch packet.tag {
            case .compressed:
                let algID = packet.body.first ?? 0
                guard let alg = CompressionAlgorithm(rawValue: algID) else {
                    throw OpenPGPError.unsupported("compression algorithm \(algID)")
                }
                let inflated = try Decompress.decompress(Array(packet.body.dropFirst()), algorithm: alg)
                return try extractLiteral(from: inflated)
            case .literal:
                return try literalContents(packet.body)
            default:
                continue
            }
        }
        throw OpenPGPError.malformed("no literal data packet")
    }

    private func literalContents(_ body: [UInt8]) throws -> Data {
        var r = ByteReader(body)
        _ = try r.readByte()                 // format ('b', 't', 'u')
        let nameLen = Int(try r.readByte())
        _ = try r.read(nameLen)              // file name
        _ = try r.readUInt32()               // timestamp
        return Data(r.readToEnd())
    }
}
