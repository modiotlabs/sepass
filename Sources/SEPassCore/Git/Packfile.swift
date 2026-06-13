import Foundation
import CryptoKit

enum GitObjectType: UInt8 {
    case commit = 1, tree = 2, blob = 3, tag = 4
    var name: String {
        switch self {
        case .commit: return "commit"; case .tree: return "tree"
        case .blob: return "blob"; case .tag: return "tag"
        }
    }
}

struct GitObject {
    let type: GitObjectType
    let data: [UInt8]
    /// Git object id: SHA-1 over "<type> <size>\0<data>".
    var sha: String {
        var h = Insecure.SHA1()
        h.update(data: Data("\(type.name) \(data.count)\0".utf8))
        h.update(data: Data(data))
        return h.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// Decodes a (non-thin) git packfile into a map of object id → object, resolving both
/// offset and reference deltas. Full clones produce self-contained packs, so every
/// delta base is present here.
enum Packfile {
    private enum Raw {
        case undeltified(GitObjectType, [UInt8])
        case ofsDelta(baseOffset: Int, delta: [UInt8])
        case refDelta(baseSha: String, delta: [UInt8])
    }

    static func parse(_ pack: [UInt8]) throws -> [String: GitObject] {
        guard pack.count > 32, Array(pack[0..<4]) == Array("PACK".utf8) else {
            throw GitError.packError("bad signature")
        }
        let count = Int(pack[8]) << 24 | Int(pack[9]) << 16 | Int(pack[10]) << 8 | Int(pack[11])

        var entries: [Int: Raw] = [:]      // pack offset → raw entry
        var order: [Int] = []
        var index = 12
        for _ in 0..<count {
            let objectOffset = index
            let (type, _, headerLen) = try readObjectHeader(pack, at: index)
            index += headerLen
            switch type {
            case 6: // OFS_DELTA: negative offset to a base earlier in the pack
                let (relOffset, n) = readOffset(pack, at: index)
                index += n
                let (delta, consumed) = try ZlibStream.inflate(pack[index...])
                index += consumed
                entries[objectOffset] = .ofsDelta(baseOffset: objectOffset - relOffset, delta: delta)
            case 7: // REF_DELTA: 20-byte base object id
                let baseSha = pack[index..<index + 20].map { String(format: "%02x", $0) }.joined()
                index += 20
                let (delta, consumed) = try ZlibStream.inflate(pack[index...])
                index += consumed
                entries[objectOffset] = .refDelta(baseSha: baseSha, delta: delta)
            default:
                guard let objType = GitObjectType(rawValue: UInt8(type)) else {
                    throw GitError.packError("unknown object type \(type)")
                }
                let (data, consumed) = try ZlibStream.inflate(pack[index...])
                index += consumed
                entries[objectOffset] = .undeltified(objType, data)
            }
            order.append(objectOffset)
        }

        // Resolve to full objects, memoized by offset, indexed by sha.
        var byOffset: [Int: GitObject] = [:]
        var shaToOffset: [String: Int] = [:]

        func resolve(_ offset: Int) throws -> GitObject {
            if let obj = byOffset[offset] { return obj }
            guard let raw = entries[offset] else { throw GitError.packError("missing offset \(offset)") }
            let obj: GitObject
            switch raw {
            case .undeltified(let type, let data):
                obj = GitObject(type: type, data: data)
            case .ofsDelta(let baseOffset, let delta):
                let base = try resolve(baseOffset)
                obj = GitObject(type: base.type, data: try applyDelta(base: base.data, delta: delta))
            case .refDelta(let baseSha, let delta):
                guard let baseOffset = shaToOffset[baseSha] else {
                    throw GitError.packError("thin-pack base \(baseSha) not present")
                }
                let base = try resolve(baseOffset)
                obj = GitObject(type: base.type, data: try applyDelta(base: base.data, delta: delta))
            }
            byOffset[offset] = obj
            shaToOffset[obj.sha] = offset
            return obj
        }

        // First pass: undeltified + ofs-delta (offset-resolvable) so shaToOffset fills;
        // second pass: ref-deltas, whose bases are now indexed.
        for offset in order {
            if case .refDelta = entries[offset] { continue }
            _ = try resolve(offset)
        }
        var result: [String: GitObject] = [:]
        for offset in order { let obj = try resolve(offset); result[obj.sha] = obj }
        return result
    }

    /// Object header: 3-bit type + variable-length size (RFC-less git varint).
    private static func readObjectHeader(_ pack: [UInt8], at start: Int) throws -> (type: Int, size: Int, length: Int) {
        var i = start
        let first = Int(pack[i]); i += 1
        let type = (first >> 4) & 0x07
        var size = first & 0x0f
        var shift = 4
        var byte = first
        while byte & 0x80 != 0 {
            byte = Int(pack[i]); i += 1
            size |= (byte & 0x7f) << shift
            shift += 7
        }
        return (type, size, i - start)
    }

    /// OFS_DELTA base offset encoding.
    private static func readOffset(_ pack: [UInt8], at start: Int) -> (offset: Int, length: Int) {
        var i = start
        var byte = Int(pack[i]); i += 1
        var offset = byte & 0x7f
        while byte & 0x80 != 0 {
            byte = Int(pack[i]); i += 1
            offset = ((offset + 1) << 7) | (byte & 0x7f)
        }
        return (offset, i - start)
    }

    /// Apply a git delta (copy/insert opcodes) to a base object.
    private static func applyDelta(base: [UInt8], delta: [UInt8]) throws -> [UInt8] {
        var i = 0
        func readVarint() -> Int {
            var value = 0, shift = 0, byte = 0
            repeat {
                byte = Int(delta[i]); i += 1
                value |= (byte & 0x7f) << shift
                shift += 7
            } while byte & 0x80 != 0
            return value
        }
        _ = readVarint()                       // source size (unused; we trust base)
        let targetSize = readVarint()
        var out = [UInt8](); out.reserveCapacity(targetSize)
        while i < delta.count {
            let opcode = Int(delta[i]); i += 1
            if opcode & 0x80 != 0 {            // copy from base
                var copyOffset = 0, copySize = 0
                if opcode & 0x01 != 0 { copyOffset |= Int(delta[i]); i += 1 }
                if opcode & 0x02 != 0 { copyOffset |= Int(delta[i]) << 8; i += 1 }
                if opcode & 0x04 != 0 { copyOffset |= Int(delta[i]) << 16; i += 1 }
                if opcode & 0x08 != 0 { copyOffset |= Int(delta[i]) << 24; i += 1 }
                if opcode & 0x10 != 0 { copySize |= Int(delta[i]); i += 1 }
                if opcode & 0x20 != 0 { copySize |= Int(delta[i]) << 8; i += 1 }
                if opcode & 0x40 != 0 { copySize |= Int(delta[i]) << 16; i += 1 }
                if copySize == 0 { copySize = 0x10000 }
                out += base[copyOffset..<copyOffset + copySize]
            } else if opcode != 0 {           // insert literal bytes from the delta
                out += delta[i..<i + opcode]; i += opcode
            } else {
                throw GitError.packError("invalid delta opcode 0")
            }
        }
        guard out.count == targetSize else { throw GitError.packError("delta size mismatch") }
        return out
    }
}
