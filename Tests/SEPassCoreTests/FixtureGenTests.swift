import Foundation
import XCTest
import CryptoKit
@testable import SEPassCore

/// Regenerates the committed decryption fixture (a fixed key + a gpg-produced
/// ciphertext) used by the hermetic `HermeticDecryptTests`. Only runs when
/// SEPASS_REGEN=1 and gpg is present; otherwise skipped, so normal `swift test`
/// runs never depend on it.
final class FixtureGenTests: XCTestCase {

    /// A fixed (test-only) P-256 scalar so the fixture is reproducible.
    static let fixedScalar = [UInt8](repeating: 0x42, count: 32)

    func testRegenerateFixture() throws {
        guard ProcessInfo.processInfo.environment["SEPASS_REGEN"] == "1" else {
            throw XCTSkip("set SEPASS_REGEN=1 to regenerate fixtures")
        }
        guard GPG.path() != nil else { throw XCTSkip("gpg not installed") }

        let agreement = try SoftwareP256KeyAgreement(rawRepresentation: Data(Self.fixedScalar))
        let signer = SoftwareP256Signer()
        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement,
            userID: "SE Pass Fixture <fixture@example.com>", creationTime: 1_700_000_000)

        let home = try GPG.makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try GPG.run(["--import"], home: home, input: material.armoredPublicKey.data(using: .utf8)!)
        let plaintext = "fixture-secret-🔐\nlogin: alice\n"
        let enc = try GPG.run(["--encrypt", "--recipient",
                               material.primaryFingerprint.map { String(format: "%02X", $0) }.joined(),
                               "--trust-model", "always"],
                              home: home, input: plaintext.data(using: .utf8)!)

        let dir = Self.fixtureDir()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try enc.stdout.write(to: dir.appendingPathComponent("message.gpg"))
        let meta: [String: Any] = [
            "scalarHex": Self.fixedScalar.map { String(format: "%02x", $0) }.joined(),
            "subkeyFingerprintHex": material.recipient.fingerprint.map { String(format: "%02x", $0) }.joined(),
            "subkeyKeyIDHex": material.recipient.keyID.map { String(format: "%02x", $0) }.joined(),
            "kdfHash": Int(material.recipient.kdfHash.rawValue),
            "kdfSymmetric": Int(material.recipient.kdfSymmetric.rawValue),
            "plaintext": plaintext,
        ]
        let data = try JSONSerialization.data(withJSONObject: meta, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: dir.appendingPathComponent("meta.json"))
        print("wrote fixture to \(dir.path)")
    }

    /// Path to the *source* Fixtures directory (not the build copy), derived from this
    /// file's location so regeneration updates the committed fixture.
    static func fixtureDir() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Fixtures")
            .appendingPathComponent("decrypt")
    }
}
