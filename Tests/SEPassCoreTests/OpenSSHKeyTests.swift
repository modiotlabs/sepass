import Foundation
import XCTest
import CryptoKit
@testable import SEPassCore

/// Validates the OpenSSH public-key encoding against the real `ssh-keygen`, so the
/// deploy key SE Pass shows the user is genuinely well-formed and fingerprints match.
final class OpenSSHKeyTests: XCTestCase {

    private func sshKeygen() -> String? {
        for c in ["/usr/bin/ssh-keygen", "/opt/homebrew/bin/ssh-keygen"]
        where FileManager.default.isExecutableFile(atPath: c) { return c }
        return nil
    }

    func testAuthorizedKeyParsesAndFingerprintMatches() throws {
        guard let keygen = sshKeygen() else { throw XCTSkip("ssh-keygen not available") }

        let signer = SoftwareP256Signer()
        let point = signer.publicKeyPoint
        let line = OpenSSHKey.authorizedKey(point: point, comment: "sepass-test")

        let file = FileManager.default.temporaryDirectory.appendingPathComponent("k-\(UUID().uuidString).pub")
        defer { try? FileManager.default.removeItem(at: file) }
        try line.write(to: file, atomically: true, encoding: .utf8)

        // ssh-keygen -l prints "<bits> SHA256:<fp> <comment> (ECDSA)" and fails on a
        // malformed key, so this checks both well-formedness and the fingerprint.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: keygen)
        p.arguments = ["-l", "-f", file.path]
        let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
        try p.run()
        let result = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 0, "ssh-keygen rejected the key: \(result)")
        XCTAssertTrue(result.contains("ECDSA"), "expected ECDSA key type: \(result)")

        let ourFingerprint = OpenSSHKey.sha256Fingerprint(ofBlob: OpenSSHKey.ecdsaP256Blob(point: point))
        XCTAssertTrue(result.contains(ourFingerprint),
                      "fingerprint mismatch.\nssh-keygen: \(result)\nours: \(ourFingerprint)")
    }
}
