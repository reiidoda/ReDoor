import Foundation

enum PQHandshakePolicy: String, CaseIterable, Identifiable {
    case prefer = "prefer"
    case required = "required"
    case disabled = "disabled"

    static let environmentKey = "REDOOR_PQ_HANDSHAKE_POLICY"

    var id: String { rawValue }

    static func resolve(from rawValue: String?) -> PQHandshakePolicy {
        guard let rawValue else { return .prefer }
        let normalized = rawValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !normalized.isEmpty else { return .prefer }
        switch normalized {
        case "required", "require", "strict":
            return .required
        case "disabled", "disable", "off", "false", "0":
            return .disabled
        default:
            return .prefer
        }
    }

    static var current: PQHandshakePolicy {
        resolve(from: ProcessInfo.processInfo.environment[environmentKey])
    }

    var displayName: String {
        switch self {
        case .prefer:
            return "Prefer Hybrid"
        case .required:
            return "Require Hybrid"
        case .disabled:
            return "Classic Only"
        }
    }

    var summary: String {
        switch self {
        case .prefer:
            return "Use hybrid PQ handshake when peer supports it; fall back to classic compatibility."
        case .required:
            return "Fail closed unless negotiated handshake mode is hybrid."
        case .disabled:
            return "Disable PQ handshake and use classic mode only."
        }
    }
}
