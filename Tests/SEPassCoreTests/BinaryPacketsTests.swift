import Foundation
import XCTest
@testable import SEPassCore

/// Unit tests for the armor-vs-binary input detection that lets one decrypt path serve
/// both the `pass`/gpg (binary) and `prs`/rpgp (ASCII-armored) backends.
final class BinaryPacketsTests: XCTestCase {

    /// Binary OpenPGP (first byte's high bit set) must pass through untouched — never
    /// mistaken for armor, byte-for-byte identical.
    func testBinaryPassThroughUnchanged() throws {
        // A range of realistic leading header bytes (old- and new-format tags).
        for lead: UInt8 in [0x85, 0xc1, 0xc2, 0xd2, 0x99, 0xa3, 0x80, 0xff] {
            let input: [UInt8] = [lead, 0x00, 0x01, 0x02, 0x03]
            XCTAssertEqual(try PGPDecryptor.binaryPackets(from: input), input,
                           "binary lead 0x\(String(lead, radix: 16)) was altered")
        }
    }

    /// An armored blob (optionally with leading whitespace) is de-armored back to the
    /// exact original binary payload.
    func testArmoredIsDearmored() throws {
        let payload: [UInt8] = (0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
        let armored = Armor.encode(payload, header: "PGP MESSAGE")

        XCTAssertEqual(try PGPDecryptor.binaryPackets(from: [UInt8](armored.utf8)), payload)

        // Leading whitespace/newlines before the BEGIN line are tolerated.
        let padded = "\n\r  \t" + armored
        XCTAssertEqual(try PGPDecryptor.binaryPackets(from: [UInt8](padded.utf8)), payload)
    }

    /// Empty / all-whitespace input is handed through (the packet parser reports it),
    /// not crashed on.
    func testEmptyAndWhitespaceArePassedThrough() throws {
        XCTAssertEqual(try PGPDecryptor.binaryPackets(from: []), [])
        let ws: [UInt8] = [0x20, 0x09, 0x0d, 0x0a]
        XCTAssertEqual(try PGPDecryptor.binaryPackets(from: ws), ws)
    }
}
