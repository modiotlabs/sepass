import Foundation

/// ASCII armor (RFC 4880 §6): base64 of the binary packets plus a CRC-24 checksum,
/// wrapped in BEGIN/END lines. SE Pass produces armored public keys for export and
/// can dearmor input, though `pass` stores binary `.gpg` files.
enum Armor {
    static func armorPublicKey(_ data: [UInt8]) -> String {
        encode(data, header: "PGP PUBLIC KEY BLOCK")
    }

    static func encode(_ data: [UInt8], header: String) -> String {
        let base64 = Data(data).base64EncodedString()
        let wrapped = stride(from: 0, to: base64.count, by: 64).map { start -> String in
            let s = base64.index(base64.startIndex, offsetBy: start)
            let e = base64.index(s, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            return String(base64[s..<e])
        }.joined(separator: "\n")
        let crc = "=" + Data(crc24(data)).base64EncodedString()
        return """
        -----BEGIN \(header)-----

        \(wrapped)
        \(crc)
        -----END \(header)-----
        """
    }

    /// Strip armor and return the binary payload. Tolerant of CRLF and stray spaces.
    static func dearmor(_ text: String) throws -> [UInt8] {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let begin = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN") }),
              let end = lines.firstIndex(where: { $0.hasPrefix("-----END") }), end > begin else {
            throw OpenPGPError.malformed("missing armor delimiters")
        }
        var base64 = ""
        // Skip the BEGIN line, then any "Header: value" lines and the blank separator.
        var inHeaders = true
        for line in lines[(begin + 1)..<end] {
            if inHeaders {
                if line.isEmpty { inHeaders = false; continue }
                if line.contains(":") { continue }
                inHeaders = false
            }
            if line.hasPrefix("=") { break } // CRC line ends the payload
            base64 += line
        }
        guard let data = Data(base64Encoded: base64) else {
            throw OpenPGPError.malformed("invalid base64 in armor")
        }
        return [UInt8](data)
    }

    /// CRC-24 as specified in RFC 4880 §6.1.
    static func crc24(_ data: [UInt8]) -> [UInt8] {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 { crc ^= 0x1864CFB }
            }
        }
        crc &= 0xFFFFFF
        return [UInt8(crc >> 16 & 0xff), UInt8(crc >> 8 & 0xff), UInt8(crc & 0xff)]
    }
}
