import Foundation

/// OpenPGP Multiprecision Integers (RFC 4880 §3.2): a 2-byte big-endian bit count
/// followed by the minimal big-endian magnitude bytes.
///
/// For the ECC algorithms SE Pass uses, EC points are carried inside an MPI as the
/// SEC1 uncompressed encoding `0x04 ‖ X ‖ Y` (RFC 6637 §6), so the same machinery
/// serves both plain integers and points.
enum MPI {
    /// Encode raw magnitude bytes (already big-endian, e.g. an EC point) as an MPI.
    static func encode(_ magnitude: [UInt8]) -> [UInt8] {
        // Strip leading zero bytes to get the canonical minimal form.
        var bytes = magnitude
        while bytes.count > 1 && bytes.first == 0 { bytes.removeFirst() }

        let bitLength: Int
        if let first = bytes.first, first != 0 {
            // leadingZeroBitCount on UInt8 is 8-bit based, so the top set bit is at
            // position (8 - leadingZeroBitCount) within the leading byte.
            let leadingBits = 8 - Int(first.leadingZeroBitCount)
            bitLength = (bytes.count - 1) * 8 + leadingBits
        } else {
            bitLength = 0
        }
        return bitLength.be2 + bytes
    }
}

extension ByteReader {
    /// Read an MPI and return its raw magnitude bytes (left-padded to the declared
    /// byte length so EC points keep their full fixed width).
    mutating func readMPI() throws -> [UInt8] {
        let bitLength = try readUInt16()
        let byteCount = (bitLength + 7) / 8
        return try read(byteCount)
    }
}
