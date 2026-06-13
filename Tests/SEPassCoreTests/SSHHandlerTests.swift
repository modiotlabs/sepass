import Foundation
import XCTest
import NIOCore
import NIOEmbedded
import NIOSSH
@testable import SEPassCore

/// Unit-tests the SSH channel handler's custom logic with an EmbeddedChannel: it must
/// split the ref advertisement (terminated by a flush-pkt) from the packfile, wrap
/// outbound request bytes as SSHChannelData, and deliver the pack on channel EOF. The
/// swift-nio-ssh handshake/auth/exec around it is library code we trust.
final class SSHHandlerTests: XCTestCase {

    func testSplitsAdvertisementThenDeliversPackOnEOF() throws {
        let loop = EmbeddedEventLoop()
        let advPromise = loop.makePromise(of: [UInt8].self)
        let packPromise = loop.makePromise(of: [UInt8].self)
        let handler = GitSSHDataHandler(command: "git-upload-pack 'x'",
                                        advertisement: advPromise, pack: packPromise)
        let channel = EmbeddedChannel(handler: handler, loop: loop)
        try channel.connect(to: try SocketAddress(ipAddress: "127.0.0.1", port: 1)).wait()

        // Server sends a ref advertisement terminated by a flush-pkt.
        let advertisement = PktLine.encode("\(String(repeating: "a", count: 40)) HEAD\u{0}symref=HEAD:refs/heads/main\n")
            + PktLine.encode("\(String(repeating: "a", count: 40)) refs/heads/main\n")
            + PktLine.flush
        try channel.writeInbound(sshData(advertisement, channel: channel))

        let gotAdvertisement = try advPromise.futureResult.wait()
        XCTAssertEqual(gotAdvertisement, advertisement)

        // Client writes the want/done request; it must come out wrapped as SSHChannelData.
        let request = PktLine.encode("want \(String(repeating: "a", count: 40)) ofs-delta\n") + PktLine.flush + PktLine.encode("done\n")
        var reqBuf = channel.allocator.buffer(capacity: request.count); reqBuf.writeBytes(request)
        try channel.writeOutbound(reqBuf)
        let outbound: SSHChannelData? = try channel.readOutbound()
        guard case .byteBuffer(let outBuf)? = outbound?.data else { return XCTFail("no wrapped outbound") }
        XCTAssertEqual(Array(outBuf.readableBytesView), request)

        // Server streams the pack (NAK + PACK …) then closes; pack is delivered on EOF.
        let pack = PktLine.encode("NAK\n") + Array("PACK\u{0}\u{0}\u{0}\u{2}rest-of-pack".utf8)
        try channel.writeInbound(sshData(pack, channel: channel))
        _ = try channel.finish() // fires channelInactive (EOF)

        let gotPack = try packPromise.futureResult.wait()
        XCTAssertEqual(gotPack, pack)
    }

    private func sshData(_ bytes: [UInt8], channel: EmbeddedChannel) -> SSHChannelData {
        var buf = channel.allocator.buffer(capacity: bytes.count)
        buf.writeBytes(bytes)
        return SSHChannelData(type: .channel, data: .byteBuffer(buf))
    }
}
