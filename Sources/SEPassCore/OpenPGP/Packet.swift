import Foundation

/// A parsed OpenPGP packet: its tag plus the raw body bytes (header stripped).
struct Packet {
    let tag: PacketTag
    let body: [UInt8]
}

enum PacketParser {
    /// Split a binary OpenPGP message into top-level packets. Handles both the
    /// old-format (RFC 4880 §4.2.1) and new-format (§4.2.2) headers, including the
    /// new-format partial body lengths used for streamed/compressed data.
    static func parse(_ data: [UInt8]) throws -> [Packet] {
        var reader = ByteReader(data)
        var packets: [Packet] = []
        while !reader.isAtEnd {
            let header = try reader.readByte()
            guard header & 0x80 != 0 else {
                throw OpenPGPError.malformed("packet header high bit not set")
            }
            let newFormat = header & 0x40 != 0
            let rawTag: UInt8
            var body: [UInt8]

            if newFormat {
                rawTag = header & 0x3f
                body = try readNewFormatBody(&reader)
            } else {
                rawTag = (header >> 2) & 0x0f
                let lengthType = header & 0x03
                let length: Int
                switch lengthType {
                case 0: length = Int(try reader.readByte())
                case 1: length = try reader.readUInt16()
                case 2: length = Int(try reader.readUInt32())
                default: // indeterminate length: consume the rest of the stream
                    length = reader.remaining
                }
                body = try reader.read(length)
            }

            if let tag = PacketTag(rawValue: rawTag) {
                packets.append(Packet(tag: tag, body: body))
            }
            // Unknown tags are skipped — their length was still consumed above.
        }
        return packets
    }

    /// New-format body length parsing, accumulating partial body lengths (§4.2.2.4).
    private static func readNewFormatBody(_ reader: inout ByteReader) throws -> [UInt8] {
        var body: [UInt8] = []
        while true {
            let first = try reader.readByte()
            switch first {
            case 0...191:
                body += try reader.read(Int(first))
                return body
            case 192...223:
                let second = try reader.readByte()
                let length = (Int(first) - 192) << 8 + Int(second) + 192
                body += try reader.read(length)
                return body
            case 255:
                let length = Int(try reader.readUInt32())
                body += try reader.read(length)
                return body
            default: // 224...254: partial body length, more chunks follow
                let length = 1 << (Int(first) & 0x1f)
                body += try reader.read(length)
                continue
            }
        }
    }

    /// Serialize a packet with a new-format header and a one-/two-/five-byte length.
    static func serialize(tag: PacketTag, body: [UInt8]) -> [UInt8] {
        let header: UInt8 = 0xc0 | tag.rawValue
        return [header] + encodeNewFormatLength(body.count) + body
    }

    private static func encodeNewFormatLength(_ length: Int) -> [UInt8] {
        switch length {
        case 0...191:
            return [UInt8(length)]
        case 192...8383:
            let l = length - 192
            return [UInt8((l >> 8) + 192), UInt8(l & 0xff)]
        default:
            return [0xff] + UInt32(length).be4
        }
    }
}
