import Foundation
import XCTest
@testable import SEPassCore

/// Drives the pure-Swift clone against a real `git upload-pack` over a process pipe.
/// `git upload-pack --stateless-rpc` uses the identical wire protocol as HTTP and SSH,
/// so this validates pkt-line negotiation, packfile/delta decode, and checkout end to
/// end without any network.
final class GitCloneTests: XCTestCase {

    private func git() -> String? {
        for c in ["/opt/homebrew/bin/git", "/usr/bin/git", "/usr/local/bin/git"]
        where FileManager.default.isExecutableFile(atPath: c) { return c }
        return nil
    }

    @discardableResult
    private func runGit(_ args: [String], cwd: URL? = nil) throws -> Data {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: git()!)
        p.arguments = args
        if let cwd { p.currentDirectoryURL = cwd }
        var env = ProcessInfo.processInfo.environment
        env["GIT_AUTHOR_NAME"] = "Test"; env["GIT_AUTHOR_EMAIL"] = "t@e.com"
        env["GIT_COMMITTER_NAME"] = "Test"; env["GIT_COMMITTER_EMAIL"] = "t@e.com"
        p.environment = env
        let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
        try p.run(); let data = out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        if p.terminationStatus != 0 { throw NSError(domain: "git", code: Int(p.terminationStatus)) }
        return data
    }

    /// Real HTTPS clone of a tiny public repo. Network-gated so the default suite stays
    /// hermetic; run with SEPASS_NET=1.
    func testClonesPublicRepoOverHTTPS() async throws {
        guard ProcessInfo.processInfo.environment["SEPASS_NET"] == "1" else {
            throw XCTSkip("set SEPASS_NET=1 to run the network clone test")
        }
        let transport = HTTPSUploadPackTransport(
            repoURL: URL(string: "https://github.com/octocat/Hello-World.git")!)
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("https-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }

        _ = try await GitCloner(transport: transport).clone(ref: nil, into: dest)
        let readme = dest.appendingPathComponent("README")
        XCTAssertTrue(FileManager.default.fileExists(atPath: readme.path),
                      "expected README in cloned tree; got \(try? FileManager.default.contentsOfDirectory(atPath: dest.path))")
    }

    func testClonesLocalRepoViaUploadPack() throws {
        guard git() != nil else { throw XCTSkip("git not installed") }

        // Build a small repo that looks like a pass store.
        let repo = FileManager.default.temporaryDirectory.appendingPathComponent("repo-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: repo) }

        let files: [String: String] = [
            ".gpg-id": "ABCDEF\n",
            "email/work.gpg": "ciphertext-1",
            "email/home.gpg": "ciphertext-2",
            "social/twitter.gpg": "ciphertext-3",
            "README": String(repeating: "pass store contents to force compression\n", count: 50),
        ]
        for (path, contents) in files {
            let url = repo.appendingPathComponent(path)
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try contents.data(using: .utf8)!.write(to: url)
        }
        try runGit(["init", "-b", "main"], cwd: repo)
        try runGit(["add", "."], cwd: repo)
        try runGit(["commit", "-m", "initial"], cwd: repo)

        // Clone it with the pure-Swift client via a process transport.
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("clone-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }
        let transport = ProcessUploadPackTransport(repoPath: repo.path, gitPath: git()!)
        let cloner = GitCloner(transport: transport)

        let expectation = expectation(description: "clone")
        Task {
            do {
                _ = try await cloner.clone(ref: "main", into: dest)
                expectation.fulfill()
            } catch { XCTFail("clone failed: \(error)"); expectation.fulfill() }
        }
        wait(for: [expectation], timeout: 30)

        // Every original file must be present and byte-identical in the clone.
        for (path, contents) in files {
            let cloned = dest.appendingPathComponent(path)
            let got = try? String(contentsOf: cloned, encoding: .utf8)
            XCTAssertEqual(got, contents, "mismatch for \(path)")
        }
    }

    /// A shallow (depth-1) clone still yields the complete working tree of the tip, and
    /// `remoteHead` reports the same commit the clone checked out — the two must agree so
    /// the refresh short-circuit is sound. Also exercises the multi-commit path so the
    /// deepen request genuinely trims history rather than getting it all anyway.
    func testShallowCloneAndRemoteHead() throws {
        guard git() != nil else { throw XCTSkip("git not installed") }

        let repo = FileManager.default.temporaryDirectory.appendingPathComponent("repo-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: repo, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: repo) }
        try runGit(["init", "-b", "main"], cwd: repo)
        try FileManager.default.createDirectory(at: repo.appendingPathComponent("email"),
                                                withIntermediateDirectories: true)

        // Several commits so a full clone would carry history the shallow one drops.
        for i in 1...3 {
            try "ciphertext-\(i)".data(using: .utf8)!
                .write(to: repo.appendingPathComponent("email/work.gpg"))
            try runGit(["add", "."], cwd: repo)
            try runGit(["commit", "-m", "commit \(i)"], cwd: repo)
        }
        let tipSha = String(decoding: try runGit(["rev-parse", "HEAD"], cwd: repo), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        let dest = FileManager.default.temporaryDirectory.appendingPathComponent("clone-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dest) }
        let cloner = GitCloner(transport: ProcessUploadPackTransport(repoPath: repo.path, gitPath: git()!))

        let expectation = expectation(description: "shallow clone")
        Task {
            do {
                let head = try await cloner.remoteHead(ref: "main")
                XCTAssertEqual(head, tipSha, "remoteHead must report the tip commit")

                let cloned = try await cloner.clone(ref: "main", into: dest)
                XCTAssertEqual(cloned, tipSha, "clone must check out the tip commit")

                // The tip's full working tree is present despite depth 1.
                let got = try String(contentsOf: dest.appendingPathComponent("email/work.gpg"), encoding: .utf8)
                XCTAssertEqual(got, "ciphertext-3")
                expectation.fulfill()
            } catch { XCTFail("shallow clone failed: \(error)"); expectation.fulfill() }
        }
        wait(for: [expectation], timeout: 30)
    }
}

/// Test transport that runs `git upload-pack --stateless-rpc`, the same stateless
/// framing the HTTP and SSH transports use.
struct ProcessUploadPackTransport: GitUploadPackTransport {
    let repoPath: String
    let gitPath: String

    func advertiseRefs() async throws -> [UInt8] {
        try run(["upload-pack", "--stateless-rpc", "--advertise-refs", repoPath], input: nil)
    }
    func fetchPack(_ requestBody: [UInt8]) async throws -> [UInt8] {
        try run(["upload-pack", "--stateless-rpc", repoPath], input: Data(requestBody))
    }

    private func run(_ args: [String], input: Data?) throws -> [UInt8] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: gitPath)
        p.arguments = args
        let out = Pipe(), err = Pipe(); p.standardOutput = out; p.standardError = err
        if let input { let inPipe = Pipe(); p.standardInput = inPipe
            try p.run(); inPipe.fileHandleForWriting.write(input); try? inPipe.fileHandleForWriting.close()
        } else { try p.run() }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return [UInt8](data)
    }
}
