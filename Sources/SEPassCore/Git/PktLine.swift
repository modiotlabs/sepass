import Foundation

/// Git's pkt-line framing (the wire format shared by the HTTP, SSH, and local
/// transports): a 4-hex-digit length prefix (counting itself) followed by the payload.
/// "0000" is a flush-pkt. SE Pass only needs the clone (`git-upload-pack`) side.
enum PktLine {
    /// Encode a payload as a single pkt-line.
    static func encode(_ payload: [UInt8]) -> [UInt8] {
        let length = payload.count + 4
        let prefix = String(format: "%04x", length)
        return Array(prefix.utf8) + payload
    }

    static func encode(_ string: String) -> [UInt8] { encode(Array(string.utf8)) }

    /// The flush-pkt that terminates a section.
    static let flush: [UInt8] = Array("0000".utf8)

    /// A parsed pkt-line: either a data payload or a flush/delimiter marker.
    enum Line {
        case data([UInt8])
        case flush
    }

    /// Parse all pkt-lines from a complete buffer (clone responses are bounded, so we
    /// don't need streaming parsing).
    static func parse(_ bytes: [UInt8]) throws -> [Line] {
        var reader = ByteReader(bytes)
        var lines: [Line] = []
        while reader.remaining >= 4 {
            let lengthHex = String(decoding: try reader.read(4), as: UTF8.self)
            guard let length = Int(lengthHex, radix: 16) else {
                throw GitError.protocolError("bad pkt-line length \(lengthHex)")
            }
            if length == 0 { lines.append(.flush); continue }      // flush-pkt
            if length == 1 || length == 2 { continue }             // delim/response-end (v2)
            guard length >= 4 else { throw GitError.protocolError("pkt-line length < 4") }
            let payload = try reader.read(length - 4)
            lines.append(.data(payload))
        }
        return lines
    }
}

/// Errors from the pure-Swift git client.
public enum GitError: Error, LocalizedError, CustomStringConvertible {
    public var errorDescription: String? { description }

    case protocolError(String)
    case packError(String)
    case transport(String)
    case refNotFound(String)
    case hostKeyRejected(String)

    public var description: String {
        switch self {
        case .protocolError(let m): return "git protocol error: \(m)"
        case .packError(let m): return "packfile error: \(m)"
        case .transport(let m): return "transport error: \(m)"
        case .refNotFound(let m): return "ref not found: \(m)"
        case .hostKeyRejected(let m): return "host key rejected: \(m)"
        }
    }
}
