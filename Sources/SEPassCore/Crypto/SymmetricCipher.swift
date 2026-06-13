import Foundation
import CommonCrypto

/// Symmetric primitives the OpenPGP message layer needs, backed by CommonCrypto.
/// CryptoKit doesn't expose raw AES-ECB or AES key-wrap, so we use CommonCrypto here.
enum SymmetricCipher {

    /// AES Key Unwrap (RFC 3394) with the default IV — recovers the padded OpenPGP
    /// session-key material wrapped by an ECDH sender.
    static func aesKeyUnwrap(kek: [UInt8], wrapped: [UInt8]) throws -> [UInt8] {
        var rawLen = CCSymmetricUnwrappedSize(CCWrappingAlgorithm(kCCWRAPAES), wrapped.count)
        var raw = [UInt8](repeating: 0, count: rawLen)
        let status = CCSymmetricKeyUnwrap(
            CCWrappingAlgorithm(kCCWRAPAES),
            CCrfc3394_iv, CCrfc3394_ivLen,
            kek, kek.count,
            wrapped, wrapped.count,
            &raw, &rawLen)
        guard status == kCCSuccess else { throw OpenPGPError.malformed("AES key unwrap failed (\(status))") }
        return Array(raw.prefix(rawLen))
    }

    /// Encrypt a single AES block in ECB mode — the building block for OpenPGP's
    /// full-block CFB (which uses the cipher's *encrypt* function in both directions).
    static func aesEncryptBlock(key: [UInt8], block: [UInt8]) throws -> [UInt8] {
        precondition(block.count == kCCBlockSizeAES128)
        var out = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        var moved = 0
        let status = CCCrypt(
            CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            key, key.count, nil,
            block, block.count,
            &out, out.count, &moved)
        guard status == kCCSuccess, moved == kCCBlockSizeAES128 else {
            throw OpenPGPError.malformed("AES ECB block failed (\(status))")
        }
        return out
    }

    /// OpenPGP full-block CFB *decryption* with a zero IV (RFC 4880 §13.9, as used by
    /// SEIPD packets). Implemented over AES-ECB so the feedback width is unambiguous.
    static func cfbDecrypt(key: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        let bs = kCCBlockSizeAES128
        var feedback = [UInt8](repeating: 0, count: bs) // zero IV
        var plaintext = [UInt8]()
        plaintext.reserveCapacity(ciphertext.count)

        var i = 0
        while i < ciphertext.count {
            let keystream = try aesEncryptBlock(key: key, block: feedback)
            let n = min(bs, ciphertext.count - i)
            for j in 0..<n {
                plaintext.append(ciphertext[i + j] ^ keystream[j])
            }
            // Feedback for the next block is this block's ciphertext.
            if n == bs {
                feedback = Array(ciphertext[i..<i + bs])
            }
            i += n
        }
        return plaintext
    }
}
