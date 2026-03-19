import Foundation

enum IdentitySecurityProfile: String, CaseIterable, Identifiable {
    case strictEphemeral = "strict_ephemeral"
    case secureEnclaveOptional = "secure_enclave_optional"

    static let environmentKey = "REDOOR_IDENTITY_PROFILE"

    var id: String { rawValue }

    static func resolve(from rawValue: String?) -> IdentitySecurityProfile {
        guard let rawValue else { return .strictEphemeral }
        let normalized = rawValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !normalized.isEmpty else { return .strictEphemeral }
        return IdentitySecurityProfile(rawValue: normalized) ?? .strictEphemeral
    }

    static var current: IdentitySecurityProfile {
        resolve(from: ProcessInfo.processInfo.environment[environmentKey])
    }

    var allowsPersistentIdentityMaterial: Bool {
        self == .secureEnclaveOptional
    }

    var displayName: String {
        switch self {
        case .strictEphemeral:
            return "Strict Ephemeral"
        case .secureEnclaveOptional:
            return "Secure Enclave Optional"
        }
    }

    var summary: String {
        switch self {
        case .strictEphemeral:
            return "RAM-only mode. Identity material is not persisted on device."
        case .secureEnclaveOptional:
            return "Device-bound mode. Wrapped identity can be persisted in Keychain."
        }
    }
}
