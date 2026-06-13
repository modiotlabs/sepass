import Foundation
import XCTest

/// Helpers for driving a real `gpg` against an isolated keyring in tests. Skips the
/// test (rather than failing) if `gpg` isn't on PATH.
enum GPG {
    struct Result { let status: Int32; let stdout: Data; let stderr: String }

    static func path() -> String? {
        for candidate in ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"] {
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        // Fall back to `which`.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["which", "gpg"]
        let pipe = Pipe(); p.standardOutput = pipe
        try? p.run(); p.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (out?.isEmpty == false) ? out : nil
    }

    /// A throwaway GNUPGHOME for one test. Kept short (under /tmp) so the gpg-agent
    /// Unix socket path stays within the ~104-char sun_path limit.
    static func makeHome() throws -> URL {
        let short = String(UUID().uuidString.prefix(8))
        let dir = URL(fileURLWithPath: "/tmp").appendingPathComponent("sgp-\(short)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        return dir
    }

    @discardableResult
    static func run(_ args: [String], home: URL, input: Data? = nil) throws -> Result {
        guard let gpg = path() else { throw XCTSkip("gpg not installed") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: gpg)
        // --no-autostart: none of our test operations (import, list, encrypt) need a
        // secret key, so we avoid launching gpg-agent entirely.
        p.arguments = ["--homedir", home.path, "--batch", "--yes", "--no-tty", "--no-autostart"] + args
        var env = ProcessInfo.processInfo.environment
        env["GNUPGHOME"] = home.path
        p.environment = env
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe; p.standardError = errPipe
        if let input { let inPipe = Pipe(); p.standardInput = inPipe
            try p.run()
            inPipe.fileHandleForWriting.write(input)
            try? inPipe.fileHandleForWriting.close()
        } else {
            try p.run()
        }
        let out = outPipe.fileHandleForReading.readDataToEndOfFile()
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        p.waitUntilExit()
        return Result(status: p.terminationStatus, stdout: out, stderr: err)
    }
}
