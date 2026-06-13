import SwiftUI

/// App info and maintenance. For now just the hard reset; author/license/version etc.
/// will live here later.
struct AboutView: View {
    @EnvironmentObject var model: AppModel
    @State private var showEraseConfirm = false
    @State private var showErasePasswordsConfirm = false

    var body: some View {
        NavigationStack {
            Form {
                aboutSection
                knownHostsSection
                Section {
                    Button(role: .destructive) { showErasePasswordsConfirm = true } label: {
                        Text("Erase Passwords").frame(maxWidth: .infinity, alignment: .center)
                    }
                } footer: {
                    Text("Deletes the cloned password store only. Your Enclave keys, pinned hosts, and sync settings are kept, so you can re-clone right away.")
                }
                Section {
                    Button(role: .destructive) { showEraseConfirm = true } label: {
                        Text("Erase All Data").frame(maxWidth: .infinity, alignment: .center)
                    }
                } footer: {
                    Text("Removes the Enclave keys (GPG + SSH), the cloned store, saved settings, and pinned hosts — resets SE Pass to first launch.")
                }
            }
            .navigationTitle("About")
            .confirmationDialog("Erase the cloned password store? Your Enclave keys and settings are kept.",
                                isPresented: $showErasePasswordsConfirm, titleVisibility: .visible) {
                Button("Erase Passwords", role: .destructive) { model.erasePasswords() }
            }
            .confirmationDialog("Erase all SE Pass data? This deletes the Enclave keys (GPG + SSH), cloned passwords, and saved settings.",
                                isPresented: $showEraseConfirm, titleVisibility: .visible) {
                Button("Erase Everything", role: .destructive) { model.eraseAll() }
            }
        }
    }

    private var aboutSection: some View {
        Section {
            Text("SE Pass is an iOS app for accessing passwords stored and managed by pass (sometimes referred to as \"GNU pass\", \"the standard unix password manager\", or \"password store\"). For more information about pass, please see [passwordstore.org](https://www.passwordstore.org/). For more information about SE Pass, please see [github.com/modiotlabs/sepass](https://github.com/modiotlabs/sepass).")
            Text("This is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed without any warranty, as detailed in the GNU General Public License.")
        }
        .font(.footnote)
    }

    @ViewBuilder
    private var knownHostsSection: some View {
        let hosts = model.knownHostList()
        Section {
            if hosts.isEmpty {
                Text("No pinned SSH hosts yet.").font(.footnote).foregroundStyle(.secondary)
            } else {
                ForEach(hosts, id: \.host) { item in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.host)
                            Text(item.fingerprint)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary).textSelection(.enabled)
                        }
                        Spacer()
                        Button(role: .destructive) { model.removeKnownHost(item.host) } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
            }
        } header: {
            Text("Known SSH Hosts")
        } footer: {
            Text("Host keys are pinned on first connect (trust-on-first-use) and checked on every clone. Delete a host only if its key legitimately changed — it will be re-pinned next time.")
        }
    }
}
