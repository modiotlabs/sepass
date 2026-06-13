import XCTest
@testable import SEPassCore

/// Minimal compile/sanity checks; real round-trip tests against gpg live in
/// GPGInteropTests.
final class SmokeTests: XCTestCase {
    func testArmorRoundTrips() throws {
        let payload: [UInt8] = Array(0..<200).map { UInt8($0 & 0xff) }
        let armored = Armor.encode(payload, header: "PGP MESSAGE")
        let back = try Armor.dearmor(armored)
        XCTAssertEqual(back, payload)
    }

    func testMPIEncodesBitLength() {
        // 0x01 0x00 → 9 bits.
        XCTAssertEqual(MPI.encode([0x01, 0x00]), [0x00, 0x09, 0x01, 0x00])
        // Leading zeros stripped.
        XCTAssertEqual(MPI.encode([0x00, 0x01]), [0x00, 0x01, 0x01])
    }
}
