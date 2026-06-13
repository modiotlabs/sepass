import Foundation
import XCTest
import CryptoKit
@testable import SEPassCore

final class KeyExportTests: XCTestCase {

    /// The exported public key must be importable by a real gpg, with a usable
    /// encryption subkey and a valid self-signature.
    func testGPGImportsExportedKey() throws {
        let signer = SoftwareP256Signer()
        let agreement = SoftwareP256KeyAgreement()
        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement,
            userID: "SE Pass Test <test@example.com>",
            creationTime: 1_700_000_000)

        let home = try GPG.makeHome()
        defer { try? FileManager.default.removeItem(at: home) }

        let importResult = try GPG.run(["--import"], home: home,
                                       input: material.armoredPublicKey.data(using: .utf8)!)
        XCTAssertEqual(importResult.status, 0, "import failed:\n\(importResult.stderr)")
        XCTAssertTrue(importResult.stderr.contains("imported") || importResult.stderr.contains("not changed"),
                      "unexpected import output:\n\(importResult.stderr)")

        // List keys and confirm an encryption-capable subkey exists.
        let list = try GPG.run(["--list-keys", "--with-colons", "--with-fingerprint"], home: home)
        let listing = String(data: list.stdout, encoding: .utf8) ?? ""
        XCTAssertTrue(listing.contains("\nsub:") || listing.contains("sub:"),
                      "no subkey in listing:\n\(listing)\nstderr:\n\(list.stderr)")
        // A subkey line whose capabilities field includes 'e' (encrypt).
        let hasEncryptSub = listing.split(separator: "\n").contains { line in
            line.hasPrefix("sub:") && line.split(separator: ":", omittingEmptySubsequences: false).count > 11
                && line.split(separator: ":", omittingEmptySubsequences: false)[11].contains("e")
        }
        XCTAssertTrue(hasEncryptSub, "no encryption subkey capability:\n\(listing)")

        // Print fingerprints for manual cross-check during development.
        print("PRIMARY FPR: \(material.primaryFingerprintHex)")
        print("SUBKEY  FPR: \(material.subkeyFingerprintHex)")
    }
}
