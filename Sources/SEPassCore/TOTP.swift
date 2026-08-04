import Foundation
import CryptoKit

/// Time-based one-time password support (RFC 6238).
///
/// pass entries sometimes double as a TOTP seed: the `pass-otp` extension stores an
/// `otpauth://` URL, and some users simply tag an entry with a `Type: totp` line.
/// When SE Pass sees either marker it treats the entry's password (the first line)
/// as the shared secret and derives the current code, shown as an extra decoded field.
public struct TOTP: Equatable {
    public enum Algorithm: String, Equatable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
    }

    /// Raw shared secret (already base32-decoded).
    public var secret: Data
    public var digits: Int
    public var period: Int
    public var algorithm: Algorithm

    public init(secret: Data, digits: Int = 6, period: Int = 30, algorithm: Algorithm = .sha1) {
        self.secret = secret
        self.digits = digits
        self.period = period
        self.algorithm = algorithm
    }

    /// The code covering `date` (default: now).
    public func code(at date: Date = Date()) -> String {
        code(counter: UInt64(date.timeIntervalSince1970 / Double(period)))
    }

    /// Seconds until the code covering `date` rolls over.
    public func secondsRemaining(at date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970.rounded(.down)) % period
    }

    public func code(counter: UInt64) -> String {
        var beCounter = counter.bigEndian
        let message = withUnsafeBytes(of: &beCounter) { Data($0) }
        let key = SymmetricKey(data: secret)

        let mac: Data
        switch algorithm {
        case .sha1:   mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: mac = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        // Dynamic truncation (RFC 4226 §5.3).
        let offset = Int(mac[mac.count - 1] & 0x0f)
        let binary = (UInt32(mac[offset] & 0x7f) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])
        let modulus = UInt32(pow(10, Double(digits)))
        return String(format: "%0\(digits)u", binary % modulus)
    }

    /// Builds a generator from a decrypted pass entry, or nil when the entry doesn't
    /// opt into TOTP (no `Type: totp` line and no `otpauth://` URL) or its secret can't
    /// be decoded. The secret source depends on the marker: an `otpauth://` URL supplies
    /// its own `secret` (and its digits/period/algorithm parameters), while a bare
    /// `Type: totp` line uses the entry's password (the first line).
    public static func fromPassEntry(_ plaintext: String) -> TOTP? {
        let lines = plaintext.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let password = lines.first, !password.isEmpty else { return nil }

        var typeMarker = false
        var urlSecret: String?
        var digits = 6, period = 30
        var algorithm: Algorithm = .sha1

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if let range = trimmed.range(of: "otpauth://", options: .caseInsensitive) {
                if let params = parseOTPAuth(String(trimmed[range.lowerBound...])) {
                    digits = params.digits; period = params.period; algorithm = params.algorithm
                    if let secret = params.secret { urlSecret = secret }
                }
            } else if isTypeTOTPLine(trimmed) {
                typeMarker = true
            }
        }

        // An otpauth:// URL carries its own secret; a bare `Type: totp` line uses the
        // password. Prefer the URL's secret when present.
        guard let secretString = urlSecret ?? (typeMarker ? password : nil),
              let secret = base32Decode(secretString) else { return nil }
        return TOTP(secret: secret, digits: digits, period: period, algorithm: algorithm)
    }

    /// A `Type: totp` line, tolerant of surrounding/interior whitespace and case.
    private static func isTypeTOTPLine(_ line: String) -> Bool {
        guard let colon = line.firstIndex(of: ":") else { return false }
        let key = line[..<colon].trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        return key.caseInsensitiveCompare("Type") == .orderedSame
            && value.caseInsensitiveCompare("totp") == .orderedSame
    }

    /// Pulls the `secret` and the optional digits/period/algorithm parameters from an
    /// `otpauth://` URL. `secret` is nil when the URL omits it.
    private static func parseOTPAuth(_ string: String) -> (secret: String?, digits: Int, period: Int, algorithm: Algorithm)? {
        guard let components = URLComponents(string: string) else { return nil }
        var secret: String?
        var digits = 6, period = 30
        var algorithm: Algorithm = .sha1
        for item in components.queryItems ?? [] {
            switch item.name.lowercased() {
            case "secret":    if let v = item.value, !v.isEmpty { secret = v }
            case "digits":    if let v = item.value.flatMap(Int.init), v > 0 { digits = v }
            case "period":    if let v = item.value.flatMap(Int.init), v > 0 { period = v }
            case "algorithm": if let v = item.value.flatMap({ Algorithm(rawValue: $0.uppercased()) }) { algorithm = v }
            default: break
            }
        }
        return (secret, digits, period, algorithm)
    }

    /// Decodes a base32 (RFC 4648) secret, ignoring spaces, padding, and case.
    /// Returns nil for empty input or any out-of-alphabet character.
    static func base32Decode(_ string: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var lookup = [Character: UInt32]()
        for (index, char) in alphabet.enumerated() { lookup[char] = UInt32(index) }

        var buffer: UInt32 = 0
        var bits = 0
        var output = Data()
        for char in string.uppercased() where char != " " && char != "=" {
            guard let value = lookup[char] else { return nil }
            buffer = (buffer << 5) | value
            bits += 5
            if bits >= 8 {
                bits -= 8
                output.append(UInt8((buffer >> UInt32(bits)) & 0xff))
            }
        }
        return output.isEmpty ? nil : output
    }
}
