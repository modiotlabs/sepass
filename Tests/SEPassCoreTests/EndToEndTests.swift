import Foundation
import XCTest
import CryptoKit
@testable import SEPassCore

/// The definitive validation: a key generated in Swift, exported, imported into a
/// real gpg, used by gpg/pass to encrypt, and decrypted back in Swift. If this
/// passes, the hand-rolled OpenPGP layer is interoperable with the real toolchain.
final class EndToEndTests: XCTestCase {

    private func fprHex(_ fpr: [UInt8]) -> String { fpr.map { String(format: "%02X", $0) }.joined() }

    /// gpg --encrypt → Swift decrypt.
    func testGPGEncryptSwiftDecrypt() throws {
        let signer = SoftwareP256Signer()
        let agreement = SoftwareP256KeyAgreement()
        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement,
            userID: "SE Pass E2E <e2e@example.com>",
            creationTime: 1_700_000_000)

        let home = try GPG.makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        let imp = try GPG.run(["--import"], home: home,
                              input: material.armoredPublicKey.data(using: .utf8)!)
        XCTAssertTrue(imp.stderr.contains("imported"), imp.stderr)

        let secret = "correct horse battery staple\nlogin: hunter2\nurl: https://example.com\n"
        let enc = try GPG.run(
            ["--encrypt", "--recipient", fprHex(material.primaryFingerprint),
             "--trust-model", "always"],
            home: home, input: secret.data(using: .utf8)!)
        XCTAssertFalse(enc.stdout.isEmpty, "gpg produced no ciphertext:\n\(enc.stderr)")

        let decryptor = PGPDecryptor(agreement: agreement, recipient: material.recipient)
        let plaintext = try decryptor.decrypt(enc.stdout)
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), secret)
    }

    /// Full `pass` workflow: pass init with our fingerprint, pass insert, then decrypt
    /// the resulting store file in Swift exactly as the app will.
    func testPassInsertSwiftDecrypt() throws {
        guard GPG.path() != nil else { throw XCTSkip("gpg not installed") }
        guard let pass = findPass() else { throw XCTSkip("pass not installed") }

        let signer = SoftwareP256Signer()
        let agreement = SoftwareP256KeyAgreement()
        let material = try OpenPGPKeyExporter.export(
            signer: signer, agreement: agreement,
            userID: "SE Pass Store <store@example.com>",
            creationTime: 1_700_000_000)

        let home = try GPG.makeHome()
        defer { try? FileManager.default.removeItem(at: home) }
        _ = try GPG.run(["--import"], home: home,
                        input: material.armoredPublicKey.data(using: .utf8)!)
        // pass/gpg must be willing to encrypt to an untrusted key, and must not try
        // to autostart gpg-agent (encryption needs no secret key, and the agent
        // socket can hang in a sandbox / on long temp paths).
        try "trust-model always\nno-autostart\n".write(to: home.appendingPathComponent("gpg.conf"),
                                                        atomically: true, encoding: .utf8)

        let store = home.appendingPathComponent("store")
        try FileManager.default.createDirectory(at: store, withIntermediateDirectories: true)
        // Inherit the full environment (PATH/HOME/etc.) and overlay only the two vars
        // we want to control — `pass` is a bash script that needs a complete env
        // (e.g. its GNU getopt lookup), and a stripped env makes it hang on stdin.
        var env = ProcessInfo.processInfo.environment
        env["GNUPGHOME"] = home.path
        env["PASSWORD_STORE_DIR"] = store.path

        try runPass(pass, ["init", fprHex(material.primaryFingerprint)], env: env)
        let secret = "s3cr3t-p@ss\notp: otpauth://totp/x\n"
        try runPass(pass, ["insert", "--multiline", "--force", "email/example"],
                    env: env, input: secret.data(using: .utf8)!)

        let gpgFile = store.appendingPathComponent("email/example.gpg")
        let ciphertext = try Data(contentsOf: gpgFile)
        let decryptor = PGPDecryptor(agreement: agreement, recipient: material.recipient)
        let plaintext = try decryptor.decrypt(ciphertext)
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), secret)
    }

    // MARK: - pass helpers

    private func findPass() -> String? {
        for c in ["/opt/homebrew/bin/pass", "/usr/local/bin/pass", "/usr/bin/pass"]
        where FileManager.default.isExecutableFile(atPath: c) { return c }
        return nil
    }

    private func runPass(_ pass: String, _ args: [String], env: [String: String], input: Data? = nil) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: pass)
        p.arguments = args
        p.environment = env
        let errPipe = Pipe(); p.standardError = errPipe
        let outPipe = Pipe(); p.standardOutput = outPipe
        if let input { let inPipe = Pipe(); p.standardInput = inPipe
            try p.run(); inPipe.fileHandleForWriting.write(input); try? inPipe.fileHandleForWriting.close()
        } else { try p.run() }
        _ = outPipe.fileHandleForReading.readDataToEndOfFile()
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        if p.terminationStatus != 0 { throw NSError(domain: "pass", code: Int(p.terminationStatus),
                                                    userInfo: [NSLocalizedDescriptionKey: "pass \(args) failed: \(err)"]) }
    }
}
