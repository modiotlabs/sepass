import Foundation
import CryptoKit

/// Builds v4 self-signatures (RFC 4880 §5.2). SE Pass only ever *makes* two kinds:
/// a positive certification over the UID and a binding over the encryption subkey,
/// both signed by the primary key via the injected `PGPSigner`.
enum SignatureBuilder {

    /// Encode one signature subpacket: length(type+data) ‖ type ‖ data.
    static func subpacket(_ type: SignatureSubpacket, _ data: [UInt8]) -> [UInt8] {
        let payload = [type.rawValue] + data
        return encodeSubpacketLength(payload.count) + payload
    }

    private static func encodeSubpacketLength(_ length: Int) -> [UInt8] {
        switch length {
        case 0...191: return [UInt8(length)]
        case 192...8383:
            let l = length - 192
            return [UInt8((l >> 8) + 192), UInt8(l & 0xff)]
        default: return [0xff] + UInt32(length).be4
        }
    }

    /// Assemble a complete signature packet body.
    ///
    /// - signedData: the key/UID material hashed *before* the signature's own data
    ///   (e.g. 0x99-prefixed primary key, then the 0xB4-prefixed UID).
    /// - hashed / unhashed: already-encoded subpacket areas.
    static func makeSignature(type: SignatureType,
                              signer: PGPSigner,
                              signedData: [UInt8],
                              hashed: [UInt8],
                              unhashed: [UInt8]) throws -> [UInt8] {
        // Fields from the start of the signature body through the hashed subpackets;
        // these are part of the hash, the rest of the packet is not.
        let sigPrefix: [UInt8] = [0x04, type.rawValue,
                                  PublicKeyAlgorithm.ecdsa.rawValue,
                                  HashAlgorithm.sha256.rawValue]
        let hashedSection = sigPrefix + hashed.count.be2 + hashed

        // RFC 4880 §5.2.4 trailer: 0x04, 0xFF, uint32(length of hashedSection).
        let trailer: [UInt8] = [0x04, 0xFF] + UInt32(hashedSection.count).be4
        let preimage = signedData + hashedSection + trailer

        // Left 16 bits of the digest are stored in the packet as a quick check.
        let digest = Array(SHA256.hash(data: Data(preimage)))
        let left16 = Array(digest.prefix(2))

        // ECDSA signature → MPI(r) ‖ MPI(s). The signer hashes the preimage itself.
        let rs = try signer.signSHA256(preimage)
        guard rs.count == 64 else { throw OpenPGPError.malformed("unexpected ECDSA signature length") }
        let r = Array(rs[0..<32]), s = Array(rs[32..<64])

        var body = hashedSection
        body += unhashed.count.be2 + unhashed
        body += left16
        body += MPI.encode(r) + MPI.encode(s)
        return body
    }
}
