import SwiftUI

/// Job #3: browse the password tree and open entries. Names are plaintext in pass, so
/// browsing and search never decrypt anything.
struct BrowseView: View {
    @EnvironmentObject var model: AppModel
    @State private var query = ""

    var body: some View {
        NavigationStack {
            Group {
                if model.nodes.isEmpty {
                    EmptyState(title: "No Passwords", systemImage: "lock.slash",
                               message: "Sync or import a store from the Sync tab.")
                } else if query.isEmpty {
                    List {
                        OutlineGroup(model.nodes, children: \.childrenOrNil) { node in
                            row(node)
                        }
                    }
                } else {
                    searchResults
                }
            }
            .navigationTitle("Passwords")
            .searchable(text: $query, prompt: "Search names")
            .navigationDestination(for: PassNode.self) { EntryDetailView(node: $0) }
        }
    }

    @ViewBuilder
    private func row(_ node: PassNode) -> some View {
        if node.isFolder {
            Label(node.name, systemImage: "folder")
        } else {
            NavigationLink(value: node) { Label(node.name, systemImage: "key") }
        }
    }

    private var searchResults: some View {
        let matches = PassStore.allEntries(model.nodes)
            .filter { $0.id.localizedCaseInsensitiveContains(query) }
        return List(matches) { node in
            NavigationLink(value: node) {
                VStack(alignment: .leading) {
                    Text(node.name)
                    Text(node.id).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

/// iOS 16-compatible stand-in for `ContentUnavailableView` (iOS 17+).
struct EmptyState: View {
    let title: String
    let systemImage: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: systemImage).font(.largeTitle).foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(message).font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(40)
    }
}
