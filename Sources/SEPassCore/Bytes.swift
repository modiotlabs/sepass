import Foundation

/// Errors raised while parsing OpenPGP byte streams.
public enum OpenPGPError: Error, Equatable {
    case truncated
    case malformed(String)
    case unsupported(String)
    case checksumMismatch
    case mdcMismatch
    case noMatchingKey
}

/// A small forward-only cursor over a byte buffer. All multi-byte integers in
/// OpenPGP are big-endian, which is what the `readUIntN` helpers assume.
struct ByteReader {
    let bytes: [UInt8]
    private(set) var offset: Int = 0

    init(_ data: [UInt8]) { self.bytes = data }
    init(_ data: Data) { self.bytes = [UInt8](data) }

    var remaining: Int { bytes.count - offset }
    var isAtEnd: Bool { offset >= bytes.count }

    mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw OpenPGPError.truncated }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func read(_ count: Int) throws -> [UInt8] {
        guard count >= 0, offset + count <= bytes.count else { throw OpenPGPError.truncated }
        defer { offset += count }
        return Array(bytes[offset..<offset + count])
    }

    mutating func readUInt16() throws -> Int {
        let hi = try readByte(), lo = try readByte()
        return Int(hi) << 8 | Int(lo)
    }

    mutating func readUInt32() throws -> UInt32 {
        let b = try read(4)
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }

    mutating func readToEnd() -> [UInt8] {
        defer { offset = bytes.count }
        return Array(bytes[offset...])
    }
}

/// Big-endian byte encodings for the fixed-width integers OpenPGP uses.
extension UInt32 {
    var be4: [UInt8] { [UInt8(self >> 24 & 0xff), UInt8(self >> 16 & 0xff), UInt8(self >> 8 & 0xff), UInt8(self & 0xff)] }
}

extension Int {
    var be2: [UInt8] { [UInt8(self >> 8 & 0xff), UInt8(self & 0xff)] }
}

extension Array where Element == UInt8 {
    var data: Data { Data(self) }
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
