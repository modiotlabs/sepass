import SwiftUI

/// App info and maintenance. For now just the hard reset; author/license/version etc.
/// will live here later.
struct AboutView: View {
    @EnvironmentObject var model: AppModel
    @State private var showEraseConfirm = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Button(role: .destructive) { showEraseConfirm = true } label: {
                        Text("Erase All Data").frame(maxWidth: .infinity, alignment: .center)
                    }
                } footer: {
                    Text("Removes the Enclave keys (GPG + SSH), the cloned store, and saved settings — resets SE Pass to first launch.")
                }
            }
            .navigationTitle("About")
            .confirmationDialog("Erase all SE Pass data? This deletes the Enclave keys (GPG + SSH), cloned passwords, and saved settings.",
                                isPresented: $showEraseConfirm, titleVisibility: .visible) {
                Button("Erase Everything", role: .destructive) { model.eraseAll() }
            }
        }
    }
}
