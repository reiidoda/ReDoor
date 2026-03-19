import Foundation

// Volatile chat model used for in-memory rendering only.
public struct Message: Identifiable, Equatable {
    public let id: UUID
    public var content: String
    public var timestamp: Date

    public init(id: UUID = UUID(), content: String, timestamp: Date = Date()) {
        self.id = id
        self.content = content
        self.timestamp = timestamp
    }
}
