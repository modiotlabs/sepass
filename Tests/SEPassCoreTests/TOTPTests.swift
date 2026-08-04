import XCTest
@testable import SEPassCore

final class TOTPTests: XCTestCase {
    // RFC 6238 Appendix B reference seeds (ASCII), one per HMAC variant.
    private let sha1Secret = Data("12345678901234567890".utf8)
    private let sha256Secret = Data("12345678901234567890123456789012".utf8)
    private let sha512Secret = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    /// RFC 6238 Appendix B test vectors (8-digit codes, 30s period).
    func testRFC6238Vectors() {
        let cases: [(time: TimeInterval, sha1: String, sha256: String, sha512: String)] = [
            (59,          "94287082", "46119246", "90693936"),
            (1111111109,  "07081804", "68084774", "25091201"),
            (1111111111,  "14050471", "67062674", "99943326"),
            (1234567890,  "89005924", "91819424", "93441116"),
            (2000000000,  "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ]
        for c in cases {
            let date = Date(timeIntervalSince1970: c.time)
            XCTAssertEqual(TOTP(secret: sha1Secret, digits: 8, algorithm: .sha1).code(at: date), c.sha1)
            XCTAssertEqual(TOTP(secret: sha256Secret, digits: 8, algorithm: .sha256).code(at: date), c.sha256)
            XCTAssertEqual(TOTP(secret: sha512Secret, digits: 8, algorithm: .sha512).code(at: date), c.sha512)
        }
    }

    func testSecondsRemaining() {
        let totp = TOTP(secret: sha1Secret)
        XCTAssertEqual(totp.secondsRemaining(at: Date(timeIntervalSince1970: 0)), 30)
        XCTAssertEqual(totp.secondsRemaining(at: Date(timeIntervalSince1970: 1)), 29)
        XCTAssertEqual(totp.secondsRemaining(at: Date(timeIntervalSince1970: 29)), 1)
    }

    func testBase32Decode() {
        // "12345678901234567890" encoded as base32.
        XCTAssertEqual(TOTP.base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), sha1Secret)
        // Tolerant of spaces, padding, and lowercase.
        XCTAssertEqual(TOTP.base32Decode("jbsw y3dp"), TOTP.base32Decode("JBSWY3DP"))
        XCTAssertEqual(TOTP.base32Decode("MFRGG==="), Data("abc".utf8))
        XCTAssertNil(TOTP.base32Decode(""))
        XCTAssertNil(TOTP.base32Decode("0189")) // 0/1/8/9 are not in the alphabet
    }

    func testFromPassEntryTypeLine() {
        // Any amount of whitespace around the marker, any case.
        let entry = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\nType:   totp\nurl: example.com"
        let totp = TOTP.fromPassEntry(entry)
        XCTAssertEqual(totp?.secret, sha1Secret)
        XCTAssertEqual(totp?.digits, 6)
        XCTAssertEqual(totp?.period, 30)
        XCTAssertEqual(totp?.algorithm, .sha1)
    }

    func testFromPassEntryOTPAuthURLUsesURLSecret() {
        // An otpauth:// URL supplies its own secret (and params); the first line is
        // ignored in this case.
        let entry = "ignored-first-line\n" +
            "otpauth://totp/ACME?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256"
        let totp = TOTP.fromPassEntry(entry)
        XCTAssertEqual(totp?.secret, sha1Secret)
        XCTAssertEqual(totp?.digits, 8)
        XCTAssertEqual(totp?.period, 60)
        XCTAssertEqual(totp?.algorithm, .sha256)
    }

    func testFromPassEntryTypeLineUsesFirstLine() {
        // A bare `Type: totp` line uses the entry's password as the secret.
        let entry = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\ntype: totp"
        XCTAssertEqual(TOTP.fromPassEntry(entry)?.secret, sha1Secret)
    }

    func testFromPassEntryOTPAuthWithoutSecretFallsBackToFirstLine() {
        // A malformed URL missing its secret still counts as opt-in; with no URL secret
        // and a `Type: totp` line present, the first line is used.
        let entry = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\notpauth://totp/ACME?digits=8\ntype: totp"
        let totp = TOTP.fromPassEntry(entry)
        XCTAssertEqual(totp?.secret, sha1Secret)
        XCTAssertEqual(totp?.digits, 8)
    }

    func testFromPassEntryNegativeCases() {
        // No marker at all.
        XCTAssertNil(TOTP.fromPassEntry("GEZDGNBVGY3TQOJQ\nuser: alice"))
        // Marker present but the secret isn't valid base32.
        XCTAssertNil(TOTP.fromPassEntry("not!base32!\nType: totp"))
        // Empty password line.
        XCTAssertNil(TOTP.fromPassEntry("\nType: totp"))
        // A "Type:" line that isn't totp.
        XCTAssertNil(TOTP.fromPassEntry("GEZDGNBVGY3TQOJQ\nType: login"))
        // An otpauth:// URL with no secret and no Type: totp line — nothing to use.
        XCTAssertNil(TOTP.fromPassEntry("GEZDGNBVGY3TQOJQ\notpauth://totp/ACME?digits=8"))
    }
}
