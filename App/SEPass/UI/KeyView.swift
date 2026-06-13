import SwiftUI
import CoreImage.CIFilterBuiltins

/// Job #1: generate the Secure Enclave keypair and export its public key.
struct KeyView: View {
    @EnvironmentObject var model: AppModel
    @State private var name = ""
    @State private var email = ""
    @State private var showDeleteConfirm = false

    var body: some View {
        NavigationStack {
            Group {
                if let info = model.keyInfo {
                    existingKey(info)
                } else {
                    generateForm
                }
            }
            .navigationTitle("Key")
        }
    }

    private var generateForm: some View {
        Form {
            Section("Identity") {
                TextField("Name", text: $name)
                TextField("Email", text: $email).keyboardType(.emailAddress).autocapitalization(.none)
            }
            Section {
                Button {
                    let uid = email.isEmpty ? name : "\(name) <\(email)>"
                    model.generateKey(userID: uid.isEmpty ? "SE Pass" : uid)
                } label: {
                    Text("Generate Key in Secure Enclave").frame(maxWidth: .infinity, alignment: .center)
                }
                .disabled(model.isBusy)
            } footer: {
                Text("The private key is created inside the Secure Enclave and can never leave this device. If you replace your phone you'll generate a new key and re-encrypt your store.")
            }
            if let error = model.keyError {
                Section {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote).foregroundStyle(.red)
                }
            }
        }
    }

    private func existingKey(_ info: StoredKeyInfo) -> some View {
        Form {
            Section("Fingerprint") {
                Text(formatted(info.primaryFingerprintHex)).font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
            Section("Public Key") {
                if let qr = qrImage(info.armoredPublicKey) {
                    qr.resizable().interpolation(.none).scaledToFit().frame(maxHeight: 220)
                        .frame(maxWidth: .infinity)
                }
                if let ascURL = writeASC(info.armoredPublicKey) {
                    ShareLink(item: ascURL, preview: SharePreview("sepass-public.asc")) {
                        Label("Share Public GPG Enclave Key (.asc)", systemImage: "square.and.arrow.up")
                            .frame(maxWidth: .infinity, alignment: .center)
                    }
                }
            }
            Section("Add to your store") {
                Text("""
                gpg --import sepass-public.asc
                pass init <existing-ids…> \(shortFingerprint(info.primaryFingerprintHex))
                pass git push
                """)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
            }
            Section {
                Button("Delete Key", role: .destructive) { showDeleteConfirm = true }
            }
        }
        .confirmationDialog("Delete this key? Passwords encrypted only to it become unreadable.",
                            isPresented: $showDeleteConfirm, titleVisibility: .visible) {
            Button("Delete Key", role: .destructive) { model.deleteKey() }
        }
    }

    /// Write the armored key to a temp file so it shares/AirDrops as a real .asc file.
    private func writeASC(_ armored: String) -> URL? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sepass-public.asc")
        do { try armored.data(using: .utf8)?.write(to: url); return url } catch { return nil }
    }

    private func formatted(_ hex: String) -> String {
        let upper = hex.uppercased()
        return stride(from: 0, to: upper.count, by: 4).map {
            let s = upper.index(upper.startIndex, offsetBy: $0)
            let e = upper.index(s, offsetBy: 4, limitedBy: upper.endIndex) ?? upper.endIndex
            return String(upper[s..<e])
        }.joined(separator: " ")
    }

    /// Abbreviated fingerprint for the example command, so the line doesn't wrap. The
    /// full fingerprint to actually use is shown in the Fingerprint section above.
    private func shortFingerprint(_ hex: String) -> String { String(hex.uppercased().prefix(8)) + "…" }

    private func qrImage(_ string: String) -> Image? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        guard let output = filter.outputImage,
              let cg = context.createCGImage(output, from: output.extent) else { return nil }
        return Image(decorative: cg, scale: 1)
    }
}
