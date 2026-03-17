import Foundation

// Legacy placeholder kept to avoid breaking references while the app remains RAM-only.
// No CoreData stack is initialized in this architecture.
struct PersistenceController {
    static let shared = PersistenceController()

    @MainActor
    static let preview = PersistenceController()
}
