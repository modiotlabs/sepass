import Foundation
import XCTest
@testable import SEPassCore

/// Live interop matrix: every backend × every on-disk format must decrypt. Each case is
/// independently gated on the tool it needs, so this runs opportunistically in dev and
/// skips cleanly in CI (where the committed fixtures in HermeticDecryptTests provide the
/// always-on guarantee for the two real-world combinations).
///
///   pass/gpg  binary   (gpg --encrypt)              ← the default `pass` store
///   pass/gpg  armored  (gpg --encrypt --armor)
///   prs/rpgp  armored  (rsop encrypt)               ← the default `prs` store
///   prs/rpgp  binary   (rsop encrypt --no-armor)
///
/// Set RSOP_BIN to an `rsop` binary (rpgpie/rpgp) to enable the prs cases.
final class BackendFormatInteropTests: XCTestCase {

    private let secret = "matrix-secret\nlogin: anon\nurl: https://example.com\n"

    private func makeKey() throws -> (SoftwareP256KeyAgreement, PGPKeyMaterial) {
        let agreement = SoftwareP256KeyAgreement()
        let material = try OpenPGPKeyExporter.export(
            signer: SoftwareP256Signer(), agreement: agreement,
            userID: "Matrix <matrix@example.com>", creationTime: 1_700_000_000)
        return (agreement, material)
    }

    private func assertDecrypts(_ ciphertext: Data, _ agreement: SoftwareP256KeyAgreement,
                                _ material: PGPKeyMaterial, _ label: String) throws {
        let plaintext = try PGPDecryptor(agreement: agreement, recipient: material.recipient).decrypt(ciphertext)
        XCTAssertEqual(String(data: plaintext, encoding: .utf8), secret, "\(label) did not round-trip")
    }

    // MARK: pass / gpg

    func testGPGBinary() throws { try runGPG(armor: false, label: "pass/gpg binary") }
    func testGPGArmored() throws { try runGPG(armor: true, label: "pass/gpg armored") }

    private func runGPG(armor: Bool, label: String) throws {
        guard GPG.path() != nil else { throw XCTSkip("gpg not installed") }
        let (agreement, material) = try makeKey()
        let home = try GPG.makeHome(); defer { try? FileManager.default.removeItem(at: home) }
        XCTAssertTrue(try GPG.run(["--import"], home: home,
            input: material.armoredPublicKey.data(using: .utf8)!).stderr.contains("imported"))
        let fpr = material.primaryFingerprint.map { String(format: "%02X", $0) }.joined()
        var args = ["--encrypt", "--recipient", fpr, "--trust-model", "always"]
        if armor { args.append("--armor") }
        let enc = try GPG.run(args, home: home, input: secret.data(using: .utf8)!)
        XCTAssertFalse(enc.stdout.isEmpty, enc.stderr)
        // Sanity-check the on-disk form matches what we intended to test.
        XCTAssertEqual(enc.stdout.first == 0x2d, armor, "\(label): unexpected armor state")
        try assertDecrypts(enc.stdout, agreement, material, label)
    }

    // MARK: prs / rpgp

    func testRPGPArmored() throws { try runRPGP(noArmor: false, label: "prs/rpgp armored") }
    func testRPGPBinary() throws { try runRPGP(noArmor: true, label: "prs/rpgp binary") }

    private func runRPGP(noArmor: Bool, label: String) throws {
        guard let rsop = ProcessInfo.processInfo.environment["RSOP_BIN"],
              FileManager.default.isExecutableFile(atPath: rsop) else {
            throw XCTSkip("set RSOP_BIN to an rsop binary")
        }
        let (agreement, material) = try makeKey()
        let dir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("matrix-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let cert = dir.appendingPathComponent("cert.asc")
        try material.armoredPublicKey.write(to: cert, atomically: true, encoding: .utf8)

        var args = ["encrypt"]; if noArmor { args.append("--no-armor") }; args.append(cert.path)
        let enc = try runProcess(rsop, args, input: secret.data(using: .utf8)!)
        XCTAssertEqual(enc.status, 0, enc.stderr)
        XCTAssertEqual(enc.stdout.first == 0x2d, !noArmor, "\(label): unexpected armor state")
        try assertDecrypts(enc.stdout, agreement, material, label)
    }

    private func runProcess(_ exe: String, _ args: [String], input: Data) throws -> (status: Int32, stdout: Data, stderr: String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        let out = Pipe(), err = Pipe(), inp = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = inp
        try p.run(); inp.fileHandleForWriting.write(input); try? inp.fileHandleForWriting.close()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        return (p.terminationStatus, o, e)
    }
}
