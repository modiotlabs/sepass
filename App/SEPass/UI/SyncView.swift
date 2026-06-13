import SwiftUI

/// Job #2: configure the remote and sync the store with git.
struct SyncView: View {
    @EnvironmentObject var model: AppModel
    @State private var url = ""
    @State private var authKind = AuthKind.none
    @State private var username = ""
    @State private var secret = ""
    @State private var branch = ""
    @State private var copiedKey = false
    @FocusState private var focus: Field?

    enum Field: Hashable { case url, branch, username, token }

    enum AuthKind: String, CaseIterable, Identifiable {
        case none = "None / public"
        case httpsToken = "HTTPS token"
        case ssh = "SSH (Enclave key)"
        var id: String { rawValue }
    }

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
            Form {
                Section("Remote") {
                    TextField("Repository URL", text: $url)
                        .autocapitalization(.none).disableAutocorrection(true)
                        .keyboardType(.URL).textContentType(.URL)
                        .focused($focus, equals: .url).submitLabel(.next)
                    TextField("Branch (optional)", text: $branch)
                        .autocapitalization(.none).disableAutocorrection(true)
                        .focused($focus, equals: .branch).submitLabel(authKind == .httpsToken ? .next : .done)
                    Picker("Auth", selection: $authKind) {
                        ForEach(AuthKind.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .onChange(of: authKind) { _ in model.saveRemote(buildRemote()) }
                    if authKind == .httpsToken {
                        TextField("Username", text: $username)
                            .autocapitalization(.none).disableAutocorrection(true)
                            .focused($focus, equals: .username).submitLabel(.next)
                        SecureField("Token", text: $secret)
                            .focused($focus, equals: .token).submitLabel(.done)
                    }
                }

                if authKind == .ssh { sshKeySection }

                Section {
                    Button {
                        focus = nil   // dismiss the keyboard so the status row isn't hidden
                        model.saveRemote(buildRemote()); model.clone()
                    } label: {
                        Text(model.hasStore ? "Refresh from Remote" : "Clone")
                            .frame(maxWidth: .infinity, alignment: .center)
                    }
                    .disabled(url.isEmpty || model.isBusy || (authKind == .ssh && !model.sshKeys.hasKey))
                } footer: {
                    Text("Clones the store and replaces the local copy. Use an https URL with a token, or an SSH URL (git@host:org/repo.git) with the Enclave key above.")
                }
                if let status = model.status {
                    Section {
                        Label(status, systemImage: model.statusIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .font(.footnote)
                            .foregroundStyle(model.statusIsError ? Color.red : Color.green)
                    }
                    .id("statusRow")
                }
            }
            .navigationTitle("Sync")
            .overlay { if model.isBusy { ProgressView() } }
            .onAppear { hydrate() }
            .onSubmit(advanceFocus)
            .scrollDismissesKeyboard(.interactively)
            .onChange(of: model.status) { newValue in
                guard newValue != nil else { return }
                withAnimation { proxy.scrollTo("statusRow", anchor: .bottom) }
            }
            }
        }
    }

    /// The fields currently on screen, in order (Username/Token only show for HTTPS token).
    private var orderedFields: [Field] {
        authKind == .httpsToken ? [.url, .branch, .username, .token] : [.url, .branch]
    }

    /// Return-key behavior: advance to the next visible field, or dismiss at the end.
    private func advanceFocus() {
        guard let f = focus, let i = orderedFields.firstIndex(of: f) else { focus = nil; return }
        let next = i + 1
        focus = orderedFields.indices.contains(next) ? orderedFields[next] : nil
    }

    @ViewBuilder
    private var sshKeySection: some View {
        Section {
            if let key = model.sshKeys.publicKeyOpenSSH {
                Text(key)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(4)
                // Copy + Share share one row so the separators stay even.
                HStack(spacing: 0) {
                    Button {
                        UIPasteboard.general.string = key
                        copiedKey = true
                        Task { try? await Task.sleep(nanoseconds: 1_500_000_000); copiedKey = false }
                    } label: {
                        Label(copiedKey ? "Copied" : "Copy", systemImage: copiedKey ? "checkmark" : "doc.on.doc")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderless)
                    Divider()
                    if let fileURL = sshKeyFile(key) {
                        ShareLink(item: fileURL) {
                            Label("Share", systemImage: "square.and.arrow.up").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderless)
                    }
                }
                .alignmentGuide(.listRowSeparatorLeading) { _ in 0 } // full-width separator
                Button(role: .destructive) { model.generateSSHKey() } label: {
                    Text("Regenerate Key").frame(maxWidth: .infinity, alignment: .center)
                }
            } else {
                Button { model.generateSSHKey() } label: {
                    Text("Generate SSH Key in Secure Enclave").frame(maxWidth: .infinity, alignment: .center)
                }
            }
        } header: {
            Text("SSH (Enclave key)")
        } footer: {
            Text("Add this public key as a read-only deploy key on your repository. The private key stays in the Secure Enclave.")
        }
    }

    /// Write the OpenSSH public key to a temp file so it shares/AirDrops as a .pub file.
    private func sshKeyFile(_ key: String) -> URL? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sepass-ssh.pub")
        do { try key.write(to: url, atomically: true, encoding: .utf8); return url } catch { return nil }
    }

    private func hydrate() {
        url = model.remote.url
        branch = model.remote.branch
        if case .httpsToken(let u, let t) = model.remote.credential { username = u; secret = t }
        // Prefer the explicitly-remembered auth mode; fall back to inferring from the URL.
        if let saved = model.remote.authMode, let mode = AuthKind(rawValue: saved) {
            authKind = mode
        } else {
            authKind = url.contains("@") && !url.contains("://") ? .ssh : .none
        }
        // Keep the URL form consistent with the auth mode.
        url = (authKind == .ssh) ? Self.sshForm(url) : Self.httpsForm(url)
    }

    /// https://host/path(.git) → git@host:path
    static func sshForm(_ url: String) -> String {
        guard let u = URL(string: url), let host = u.host, (u.scheme ?? "").hasPrefix("http") else { return url }
        let path = u.path.drop(while: { $0 == "/" })
        return path.isEmpty ? url : "git@\(host):\(path)"
    }

    /// git@host:path → https://host/path
    static func httpsForm(_ url: String) -> String {
        guard let scp = PureGitService.parseSCPStyle(url) else { return url }
        return "https://\(scp.host)/\(scp.path)"
    }

    private func buildRemote() -> GitRemote {
        // Normalize the URL to match the chosen auth so the transport can never disagree
        // with the picker (SSH ⇒ git@host:path, HTTPS/None ⇒ https://…).
        let normalized = (authKind == .ssh) ? Self.sshForm(url) : Self.httpsForm(url)
        if normalized != url { url = normalized }
        let cred: GitCredential
        switch authKind {
        case .none, .ssh: cred = .none   // SSH auth uses the Enclave key, not stored credentials
        case .httpsToken: cred = .httpsToken(username: username, token: secret)
        }
        return GitRemote(url: normalized, credential: cred, branch: branch, authMode: authKind.rawValue)
    }
}
