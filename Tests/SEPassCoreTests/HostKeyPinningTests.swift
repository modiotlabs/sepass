import Foundation
import XCTest
import NIOEmbedded
import NIOSSH
@testable import SEPassCore

final class HostKeyPinningTests: XCTestCase {
    private final class MemStore: @unchecked Sendable { var map: [String: String] = [:] }

    func testInspectorMatchesReconstructedFingerprint() throws {
        // A key built from an OpenSSH line should reflect back to the same fingerprint.
        let line = OpenSSHKey.authorizedKey(point: SoftwareP256Signer().publicKeyPoint, comment: "x")
        let key = try NIOSSHPublicKey(openSSHPublicKey: line)
        let described = HostKeyInspector.describe(key)
        XCTAssertEqual(described?.fingerprint, OpenSSHKey.sha256Fingerprint(ofOpenSSHLine: line))
    }

    func testTOFUPinsThenVerifiesThenRejects() throws {
        let loop = EmbeddedEventLoop()
        let store = MemStore()
        let policy = SSHHostKeyPolicy(knownLine: { store.map[$0] },
                                      onPin: { host, line in store.map[host] = line })
        let delegate = TOFUHostKeyDelegate(host: "example.lan", policy: policy)

        let host1 = try NIOSSHPublicKey(openSSHPublicKey:
            OpenSSHKey.authorizedKey(point: SoftwareP256Signer().publicKeyPoint, comment: "h1"))
        let host2 = try NIOSSHPublicKey(openSSHPublicKey:
            OpenSSHKey.authorizedKey(point: SoftwareP256Signer().publicKeyPoint, comment: "h2"))

        // First connect: pins and accepts.
        let p1 = loop.makePromise(of: Void.self)
        delegate.validateHostKey(hostKey: host1, validationCompletePromise: p1)
        XCTAssertNoThrow(try p1.futureResult.wait())
        XCTAssertNotNil(store.map["example.lan"])

        // Same key: accepts.
        let p2 = loop.makePromise(of: Void.self)
        delegate.validateHostKey(hostKey: host1, validationCompletePromise: p2)
        XCTAssertNoThrow(try p2.futureResult.wait())

        // Different key: rejected (possible MITM / key change).
        let p3 = loop.makePromise(of: Void.self)
        delegate.validateHostKey(hostKey: host2, validationCompletePromise: p3)
        XCTAssertThrowsError(try p3.futureResult.wait())
    }
}
