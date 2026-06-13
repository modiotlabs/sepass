import Foundation
import XCTest
@testable import SEPassCore

/// Decrypts a committed gpg-produced fixture with no external dependencies, so the
/// core decryption path is covered even where gpg isn't installed (e.g. CI).
final class HermeticDecryptTests: XCTestCase {

    func testDecryptCommittedFixture() throws {
        guard let dir = Bundle.module.url(forResource: "decrypt", withExtension: nil,
                                          subdirectory: "Fixtures") else {
            throw XCTSkip("fixture not generated (run with SEPASS_REGEN=1)")
        }
        let ciphertext = try Data(contentsOf: dir.appendingPathComponent("message.gpg"))
        let metaData = try Data(contentsOf: dir.appendingPathComponent("meta.json"))
        let meta = try JSONSerialization.jsonObject(with: metaData) as! [String: Any]

        let scalar = bytes(fromHex: meta["scalarHex"] as! String)
        let agreement = try SoftwareP256KeyAgreement(rawRepresentation: Data(scalar))
        let recipient = RecipientKey(
            fingerprint: bytes(fromHex: meta["subkeyFingerprintHex"] as! String),
            keyID: bytes(fromHex: meta["subkeyKeyIDHex"] as! String),
            kdfHash: HashAlgorithm(rawValue: UInt8(meta["kdfHash"] as! Int))!,
            kdfSymmetric: SymmetricAlgorithm(rawValue: UInt8(meta["kdfSymmetric"] as! Int))!)

        let plaintext = try PGPDecryptor(agreement: agreement, recipient: recipient).decrypt(ciphertext)
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), meta["plaintext"] as? String)
    }

    private func bytes(fromHex hex: String) -> [UInt8] {
        var result = [UInt8](); var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            result.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        return result
    }
}
