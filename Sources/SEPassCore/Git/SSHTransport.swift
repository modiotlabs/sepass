import Foundation
import CryptoKit
import NIOCore
import NIOPosix
import NIOSSH

/// `git-upload-pack` over SSH using swift-nio-ssh. Authentication is public-key, and
/// the key can be Secure-Enclave-backed (the private key never leaves the device — the
/// Enclave signs the auth challenge). One SSH session channel carries the whole
/// protocol: the server's ref advertisement, then our want/done, then the packfile.
///
/// Host-key handling is currently trust-on-first-use accept (see `AcceptAllHostKeys`);
/// persistent pinning is a follow-up (swift-nio-ssh doesn't yet expose host-key bytes
/// publicly).
public final class SSHUploadPackTransport: GitUploadPackTransport, @unchecked Sendable {
    private let host: String
    private let port: Int
    private let username: String
    private let repoPath: String
    private let privateKey: NIOSSHPrivateKey
    private let group: EventLoopGroup

    private var channel: Channel?
    private var child: Channel?
    private var handler: GitSSHDataHandler?

    private init(host: String, port: Int, username: String, repoPath: String, key: NIOSSHPrivateKey) {
        self.host = host
        self.port = port
        self.username = username
        self.repoPath = repoPath
        self.privateKey = key
        self.group = MultiThreadedEventLoopGroup.singleton
    }

    /// Authenticate with a Secure Enclave key (signing happens inside the Enclave).
    public convenience init(host: String, port: Int = 22, username: String, repoPath: String,
                            secureEnclaveKey: SecureEnclave.P256.Signing.PrivateKey) {
        self.init(host: host, port: port, username: username, repoPath: repoPath,
                  key: NIOSSHPrivateKey(secureEnclaveP256Key: secureEnclaveKey))
    }

    /// Authenticate with a software P-256 key (tests / simulator).
    public convenience init(host: String, port: Int = 22, username: String, repoPath: String,
                            softwareKey: P256.Signing.PrivateKey) {
        self.init(host: host, port: port, username: username, repoPath: repoPath,
                  key: NIOSSHPrivateKey(p256Key: softwareKey))
    }

    public func advertiseRefs() async throws -> [UInt8] {
        let advPromise = group.next().makePromise(of: [UInt8].self)
        let packPromise = group.next().makePromise(of: [UInt8].self)
        let handler = GitSSHDataHandler(command: "git-upload-pack '\(repoPath)'",
                                        advertisement: advPromise, pack: packPromise)
        self.handler = handler

        let auth = PublicKeyAuthDelegate(username: username, privateKey: privateKey)
        let server = AcceptAllHostKeys()
        let bootstrap = ClientBootstrap(group: group)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let ssh = NIOSSHHandler(
                        role: .client(.init(userAuthDelegate: auth, serverAuthDelegate: server)),
                        allocator: channel.allocator,
                        inboundChildChannelInitializer: nil)
                    try channel.pipeline.syncOperations.addHandler(ssh)
                }
            }
            .channelOption(.socketOption(.tcp_nodelay), value: 1)
            .connectTimeout(.seconds(15))

        do {
            let channel = try await bootstrap.connect(host: host, port: port).get()
            self.channel = channel
            let loop = channel.eventLoop
            let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
            let childPromise = loop.makePromise(of: Channel.self)
            sshHandler.createChannel(childPromise, channelType: .session) { childChannel, _ in
                childChannel.eventLoop.makeCompletedFuture {
                    try childChannel.pipeline.syncOperations.addHandler(handler)
                }
            }
            // Bounded: if SSH auth fails or the host stalls, the session channel never
            // opens; the deadline turns that into an error instead of an endless wait.
            self.child = try await awaitWithDeadline(childPromise.futureResult, on: loop,
                                                     seconds: 20, label: "authentication")
            return try await awaitWithDeadline(advPromise.futureResult, on: loop,
                                               seconds: 20, label: "ref advertisement")
        } catch let error as GitError {
            throw error
        } catch {
            throw GitError.transport("SSH connect/auth failed: \(error)")
        }
    }

    public func fetchPack(_ requestBody: [UInt8]) async throws -> [UInt8] {
        guard let child = self.child, let handler = self.handler else {
            throw GitError.transport("SSH channel not established")
        }
        var buffer = child.allocator.buffer(capacity: requestBody.count)
        buffer.writeBytes(requestBody)
        try await child.writeAndFlush(buffer).get()       // ByteBuffer → handler wraps as SSHChannelData
        let pack = try await awaitWithDeadline(handler.packFuture, on: child.eventLoop,
                                               seconds: 60, label: "fetch")
        try? await channel?.close().get()
        return pack
    }

    /// Await a NIO future but fail with a clear timeout error if it doesn't resolve in
    /// `seconds`. The single-completion guard runs entirely on `loop`, so it's race-free.
    private func awaitWithDeadline<T>(_ future: EventLoopFuture<T>, on loop: EventLoop,
                                      seconds: Int64, label: String) async throws -> T {
        let result = loop.makePromise(of: T.self)
        // Both closures below run on `loop` (serially), so this flag is race-free. It's a
        // plain reference box (constructible off-loop), unlike NIOLoopBoundBox.
        let done = MutableFlag()
        let scheduled = loop.scheduleTask(in: .seconds(seconds)) {
            if !done.value { done.value = true; result.fail(GitError.transport("SSH \(label) timed out")) }
        }
        future.hop(to: loop).whenComplete { outcome in
            if !done.value { done.value = true; scheduled.cancel(); result.completeWith(outcome) }
        }
        return try await result.futureResult.get()
    }
}

/// A mutable boolean accessed only from a single event loop; reference semantics let it
/// be shared between the scheduled-timeout and completion closures without copying.
private final class MutableFlag: @unchecked Sendable {
    var value = false
}

// MARK: - Public-key auth (offers the key once)

private final class PublicKeyAuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private var offer: NIOSSHUserAuthenticationOffer?

    init(username: String, privateKey: NIOSSHPrivateKey) {
        offer = NIOSSHUserAuthenticationOffer(
            username: username, serviceName: "",
            offer: .privateKey(.init(privateKey: privateKey)))
    }

    func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
        if let offer, availableMethods.contains(.publicKey) {
            self.offer = nil
            nextChallengePromise.succeed(offer)
        } else {
            nextChallengePromise.succeed(nil) // no more methods → auth fails
        }
    }
}

// MARK: - Host key (TOFU accept; persistent pinning is a follow-up)

private final class AcceptAllHostKeys: NIOSSHClientServerAuthenticationDelegate, @unchecked Sendable {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

// MARK: - Channel data handler (exec + pkt-line streaming)

final class GitSSHDataHandler: ChannelDuplexHandler, @unchecked Sendable {
    typealias InboundIn = SSHChannelData
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let command: String
    private var advertisement: EventLoopPromise<[UInt8]>?
    private let pack: EventLoopPromise<[UInt8]>
    var packFuture: EventLoopFuture<[UInt8]> { pack.futureResult }

    private var buffer: [UInt8] = []
    private enum Phase { case advertising, fetching }
    private var phase: Phase = .advertising

    init(command: String, advertisement: EventLoopPromise<[UInt8]>, pack: EventLoopPromise<[UInt8]>) {
        self.command = command
        self.advertisement = advertisement
        self.pack = pack
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { _ in }
    }

    func channelActive(context: ChannelHandlerContext) {
        let exec = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: false)
        context.triggerUserOutboundEvent(exec, promise: nil)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = unwrapInboundIn(data)
        guard case .byteBuffer(let bytes) = channelData.data, channelData.type == .channel else { return }
        buffer.append(contentsOf: bytes.readableBytesView)
        if phase == .advertising, let end = advertisementEnd(buffer) {
            let adv = Array(buffer[0..<end])
            buffer.removeFirst(end)
            phase = .fetching
            advertisement?.succeed(adv)
            advertisement = nil
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let outBuffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(outBuffer))), promise: promise)
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) { finish() }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        advertisement?.fail(error); advertisement = nil
        pack.fail(error)
        context.close(promise: nil)
    }

    private func finish() {
        // EOF: the server has sent the full pack and closed the channel.
        advertisement?.fail(GitError.transport("SSH closed before advertisement")); advertisement = nil
        pack.succeed(buffer)
    }

    /// Index just past the flush-pkt that terminates the ref advertisement, or nil if
    /// the advertisement hasn't fully arrived yet.
    private func advertisementEnd(_ b: [UInt8]) -> Int? {
        var i = 0
        while i + 4 <= b.count {
            let hex = String(decoding: b[i..<i + 4], as: UTF8.self)
            guard let len = Int(hex, radix: 16) else { return nil }
            if len == 0 { return i + 4 }          // flush-pkt ends the advertisement
            if len < 4 { i += 4; continue }       // delimiter
            if i + len > b.count { return nil }    // pkt-line not fully received yet
            i += len
        }
        return nil
    }
}
