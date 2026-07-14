import SwiftUI
import UniformTypeIdentifiers
import SEPassCore

/// Decrypts one entry (triggering the biometric gate) and shows it the way pass does:
/// first line is the password, remaining lines are fields/notes.
struct EntryDetailView: View {
    @EnvironmentObject var model: AppModel
    let node: PassNode

    @State private var plaintext: String?
    @State private var error: String?
    @State private var revealed = false
    @State private var loading = false
    @State private var copied = false
    @State private var copiedCode = false

    var body: some View {
        Form {
            if let plaintext {
                let lines = plaintext.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
                let password = lines.first ?? ""
                let details = detailLines(lines)
                Section {
                    HStack {
                        Text(revealed ? password : "••••••••••")
                            .font(.system(.body, design: .monospaced))
                        Spacer()
                        Button { revealed.toggle() } label: {
                            Image(systemName: revealed ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        Button { copy(password) } label: {
                            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                .foregroundStyle(copied ? Color.green : Color.accentColor)
                        }
                        .buttonStyle(.borderless)
                    }
                } header: {
                    Text("Password")
                } footer: {
                    if copied { Text("Copied — clipboard clears in \(Int(Self.clipboardTTL))s") }
                }
                if let totp = TOTP.fromPassEntry(plaintext) {
                    Section {
                        // Recompute every second so the code and countdown stay live.
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            let code = totp.code(at: context.date)
                            HStack {
                                Text(formatCode(code))
                                    .font(.system(.title2, design: .monospaced))
                                Spacer()
                                Text("\(totp.secondsRemaining(at: context.date))s")
                                    .font(.system(.callout, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .monospacedDigit()
                                Button { copyCode(code) } label: {
                                    Image(systemName: copiedCode ? "checkmark" : "doc.on.doc")
                                        .foregroundStyle(copiedCode ? Color.green : Color.accentColor)
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                    } header: {
                        Text("One-Time Password")
                    }
                }
                if !details.isEmpty {
                    Section("Details") {
                        ForEach(Array(details.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
            } else if let error {
                Section {
                    EmptyState(title: "Couldn't Decrypt", systemImage: "exclamationmark.triangle",
                               message: error)
                }
            } else {
                Section {
                    Button {
                        Task { await decrypt() }
                    } label: {
                        // Adapts to the device: "Face ID" on Face ID phones, "Touch ID"
                        // on Touch ID phones (e.g. iPhone SE). See Biometry.
                        Label("Decrypt with \(Biometry.label)", systemImage: Biometry.iconName)
                    }
                    .disabled(loading)
                }
            }
        }
        .navigationTitle(node.name)
        .overlay { if loading { ProgressView() } }
        #if DEBUG
        .onAppear {
            guard ScreenshotFixture.isActive, plaintext == nil else { return }
            Task { await decrypt(); revealed = true }
        }
        #endif
    }

    /// Lines below the password, with trailing blank lines (from a final newline)
    /// stripped so single-line secrets don't show an empty Details section.
    private func detailLines(_ lines: [String]) -> [String] {
        var detail = Array(lines.dropFirst())
        while detail.last?.isEmpty == true { detail.removeLast() }
        return detail
    }

    /// Seconds before the copied password is auto-cleared from the clipboard, matching
    /// `pass -c`'s default.
    private static let clipboardTTL: TimeInterval = 45

    /// Groups a numeric code into two halves (e.g. `123 456`) for readability.
    private func formatCode(_ code: String) -> String {
        guard code.count > 4, code.count.isMultiple(of: 2) else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<mid]) \(code[mid...])"
    }

    private func copy(_ value: String) {
        setClipboard(value)
        flash($copied)
    }

    private func copyCode(_ value: String) {
        setClipboard(value)
        flash($copiedCode)
    }

    private func setClipboard(_ value: String) {
        // Use a system-enforced expiration so the value is removed even if the app
        // is closed, and keep it local-only so it never syncs via Universal Clipboard.
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: value]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(Self.clipboardTTL),
            ])
    }

    /// Briefly shows a confirmation checkmark on a copy button.
    private func flash(_ flag: Binding<Bool>) {
        flag.wrappedValue = true
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            flag.wrappedValue = false
        }
    }

    private func decrypt() async {
        loading = true; error = nil
        do {
            plaintext = try await model.decrypt(node)
        } catch {
            self.error = error.localizedDescription
        }
        loading = false
    }
}
