import Foundation
import Compression

/// Inflates OpenPGP Compressed Data packet payloads. gpg compresses `pass` entries
/// by default, so this sits between symmetric decryption and the literal packet.
enum Decompress {

    static func decompress(_ data: [UInt8], algorithm: CompressionAlgorithm) throws -> [UInt8] {
        switch algorithm {
        case .uncompressed:
            return data
        case .zip:
            // OpenPGP ZIP is raw DEFLATE (RFC 1951), which is exactly what
            // libcompression's COMPRESSION_ZLIB consumes.
            return try inflateRawDeflate(data)
        case .zlib:
            // OpenPGP ZLIB is a zlib stream (RFC 1950): 2-byte header + raw DEFLATE +
            // 4-byte Adler-32. Strip the header so libcompression sees raw DEFLATE.
            guard data.count > 2 else { throw OpenPGPError.malformed("short zlib stream") }
            return try inflateRawDeflate(Array(data.dropFirst(2)))
        case .bzip2:
            throw OpenPGPError.unsupported("bzip2 compression")
        }
    }

    private static func inflateRawDeflate(_ input: [UInt8]) throws -> [UInt8] {
        var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!,
                                        dst_size: 0,
                                        src_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!,
                                        src_size: 0,
                                        state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
                == COMPRESSION_STATUS_OK else {
            throw OpenPGPError.malformed("compression init failed")
        }
        defer { compression_stream_destroy(&stream) }

        let bufferSize = 64 * 1024
        var output = [UInt8]()
        return try input.withUnsafeBufferPointer { src in
            stream.src_ptr = src.baseAddress!
            stream.src_size = src.count
            var dst = [UInt8](repeating: 0, count: bufferSize)
            while true {
                let status = dst.withUnsafeMutableBufferPointer { dstBuf -> compression_status in
                    stream.dst_ptr = dstBuf.baseAddress!
                    stream.dst_size = dstBuf.count
                    let s = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                    let produced = dstBuf.count - stream.dst_size
                    output += dstBuf.prefix(produced)
                    return s
                }
                switch status {
                case COMPRESSION_STATUS_OK: continue
                case COMPRESSION_STATUS_END: return output
                default: throw OpenPGPError.malformed("inflate failed")
                }
            }
        }
    }
}
