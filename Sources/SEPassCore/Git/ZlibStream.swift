import Foundation
import Compression

/// Inflates a single zlib stream (RFC 1950) embedded in a larger buffer and reports
/// how many input bytes it consumed. Packfiles concatenate many such streams back to
/// back, so we need an exact boundary.
///
/// libcompression's streaming decoder buffers input internally, so `src_size` after it
/// reports `END` overshoots the true end of the DEFLATE stream. To get an exact
/// boundary we feed the compressed data one byte at a time and count only the bytes the
/// decoder actually consumes — it can't read past a byte we haven't handed it yet.
enum ZlibStream {
    /// - input: a slice beginning at a zlib stream (2-byte header + DEFLATE + adler32).
    /// - Returns the inflated bytes and total input consumed (header + DEFLATE + adler).
    static func inflate(_ input: ArraySlice<UInt8>) throws -> (data: [UInt8], consumed: Int) {
        let bytes = Array(input)
        guard bytes.count > 2 else { throw GitError.packError("short zlib stream") }
        let deflate = Array(bytes[2...])   // strip the 2-byte zlib header (raw DEFLATE)

        var stream = compression_stream(dst_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!,
                                        dst_size: 0,
                                        src_ptr: UnsafeMutablePointer<UInt8>(bitPattern: 1)!,
                                        src_size: 0,
                                        state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB)
                == COMPRESSION_STATUS_OK else {
            throw GitError.packError("compression init failed")
        }
        defer { compression_stream_destroy(&stream) }

        var output = [UInt8]()
        var dst = [UInt8](repeating: 0, count: 64 * 1024)
        var consumedDeflate = 0
        var src = 0
        var reachedEnd = false

        try deflate.withUnsafeBufferPointer { buf in
            while src < buf.count {
                stream.src_ptr = buf.baseAddress!.advanced(by: src)
                stream.src_size = 1                                  // one byte at a time
                let status: compression_status = dst.withUnsafeMutableBufferPointer { dstBuf in
                    stream.dst_ptr = dstBuf.baseAddress!
                    stream.dst_size = dstBuf.count
                    let s = compression_stream_process(&stream, 0)
                    output += dstBuf.prefix(dstBuf.count - stream.dst_size)
                    return s
                }
                let took = 1 - stream.src_size                      // 1 if the byte was taken, else 0
                consumedDeflate += took
                src += took                                         // advance the input cursor
                if status == COMPRESSION_STATUS_END { reachedEnd = true; break }
                if status != COMPRESSION_STATUS_OK { throw GitError.packError("inflate failed") }
                if took == 0 { throw GitError.packError("inflate stalled") }
            }
        }
        guard reachedEnd else { throw GitError.packError("unterminated zlib stream") }
        // consumed = 2 (zlib header) + DEFLATE bytes + 4 (adler32 trailer).
        return (output, 2 + consumedDeflate + 4)
    }
}
