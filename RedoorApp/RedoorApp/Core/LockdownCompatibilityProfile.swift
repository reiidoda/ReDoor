import Foundation

enum LockdownCompatibilityProfile: String, CaseIterable, Identifiable {
    case standard = "standard"
    case strict = "strict"

    static let environmentKey = "REDOOR_LOCKDOWN_PROFILE"

    var id: String { rawValue }

    static func resolve(from rawValue: String?) -> LockdownCompatibilityProfile {
        guard let rawValue else { return .standard }
        let normalized = rawValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard !normalized.isEmpty else { return .standard }
        return LockdownCompatibilityProfile(rawValue: normalized) ?? .standard
    }

    static var current: LockdownCompatibilityProfile {
        resolve(from: ProcessInfo.processInfo.environment[environmentKey])
    }

    var requiresFailClosed: Bool {
        self == .strict
    }

    var displayName: String {
        switch self {
        case .standard:
            return "Standard"
        case .strict:
            return "Strict (High-Risk)"
        }
    }

    var summary: String {
        switch self {
        case .standard:
            return "Compatibility-focused mode. Recommended defaults are reported as advisories."
        case .strict:
            return "High-risk mode. Security assumptions are enforced fail-closed when a network profile is active."
        }
    }
}

struct LockdownCompatibilitySnapshot {
    let profile: LockdownCompatibilityProfile
    let identityProfile: IdentitySecurityProfile
    let pqHandshakePolicy: PQHandshakePolicy
    let relayURL: String?
    let hmacKeyPresent: Bool
    let relaySPKIPinConfigured: Bool
    let relayCAPinConfigured: Bool
    let onionRoutingConfigured: Bool
    let strictAnonymityEnforced: Bool
    let fixedPollingEnforced: Bool
    let constantRateEnforced: Bool
    let coverHeartbeatEnabled: Bool
    let networkConfigured: Bool
}

struct LockdownCompatibilityStatus {
    let profile: LockdownCompatibilityProfile
    let checkedAt: Date
    let violations: [String]
    let advisories: [String]
    let reducedFunctionality: [String]

    var isCompatible: Bool {
        violations.isEmpty
    }

    static func initial(profile: LockdownCompatibilityProfile) -> LockdownCompatibilityStatus {
        LockdownCompatibilityStatus(
            profile: profile,
            checkedAt: Date(),
            violations: [],
            advisories: ["No network profile applied yet."],
            reducedFunctionality: []
        )
    }
}

enum LockdownCompatibilityEvaluator {
    static func evaluate(snapshot: LockdownCompatibilitySnapshot) -> LockdownCompatibilityStatus {
        var violations: [String] = []
        var advisories: [String] = []
        var reducedFunctionality: [String] = []

        let relayContext = parseRelayContext(snapshot.relayURL)

        if snapshot.profile.requiresFailClosed {
            reducedFunctionality.append("Identity profile is forced to Strict Ephemeral for active network sessions.")
            reducedFunctionality.append("PQ handshake policy should be set to Require Hybrid for downgrade resistance.")
            reducedFunctionality.append("Strict anonymity + fixed polling + constant-rate traffic must remain enabled.")
            reducedFunctionality.append("Cover heartbeat should remain enabled to preserve traffic-shape assumptions.")

            if snapshot.identityProfile != .strictEphemeral {
                violations.append("Strict lockdown requires identity profile `strict_ephemeral`.")
            }
            if snapshot.pqHandshakePolicy != .required {
                violations.append("Strict lockdown requires PQ handshake policy `required`.")
            }

            if snapshot.networkConfigured {
                if !snapshot.strictAnonymityEnforced {
                    violations.append("Strict anonymity is not enforced.")
                }
                if !snapshot.fixedPollingEnforced {
                    violations.append("Fixed polling is not enforced.")
                }
                if !snapshot.constantRateEnforced {
                    violations.append("Constant-rate traffic is not enforced.")
                }
                if !snapshot.onionRoutingConfigured {
                    violations.append("Onion routing is missing or invalid.")
                }
                if !snapshot.coverHeartbeatEnabled {
                    violations.append("Cover heartbeat is disabled.")
                }

                switch relayContext {
                case .invalid:
                    violations.append("Relay URL is invalid or missing host.")
                case .loopback:
                    advisories.append("Loopback relay profile detected; strict lockdown checks are limited in local testing mode.")
                case .remote(let secureTLS):
                    if !secureTLS {
                        violations.append("Remote relay must use HTTPS under strict lockdown profile.")
                    }
                    if !snapshot.hmacKeyPresent {
                        violations.append("Remote relay requires HMAC key under strict lockdown profile.")
                    }
                    if !snapshot.relaySPKIPinConfigured && !snapshot.relayCAPinConfigured {
                        violations.append("Remote relay requires SPKI or CA pin under strict lockdown profile.")
                    }
                }
            } else {
                advisories.append("Strict lockdown profile is active, but no network profile has been applied yet.")
            }
        } else {
            if snapshot.identityProfile != .strictEphemeral {
                advisories.append("Identity profile allows persistent material; use strict_ephemeral for high-risk deployments.")
            }
            if snapshot.pqHandshakePolicy != .required {
                advisories.append("Set PQ handshake policy to required for strongest downgrade resistance.")
            }
            if snapshot.networkConfigured {
                if !snapshot.strictAnonymityEnforced {
                    advisories.append("Strict anonymity is not enforced.")
                }
                if !snapshot.fixedPollingEnforced {
                    advisories.append("Fixed polling is not enforced.")
                }
                if !snapshot.constantRateEnforced {
                    advisories.append("Constant-rate traffic is not enforced.")
                }
                if !snapshot.onionRoutingConfigured {
                    advisories.append("Onion routing is missing or invalid.")
                }
            } else {
                advisories.append("No network profile applied yet.")
            }
        }

        return LockdownCompatibilityStatus(
            profile: snapshot.profile,
            checkedAt: Date(),
            violations: violations,
            advisories: advisories,
            reducedFunctionality: reducedFunctionality
        )
    }

    private enum RelayContext {
        case invalid
        case loopback
        case remote(secureTLS: Bool)
    }

    private static func parseRelayContext(_ relayURL: String?) -> RelayContext {
        guard let relayURL,
              let parsed = URL(string: relayURL),
              let host = parsed.host?.lowercased() else {
            return .invalid
        }

        let isLoopback = host == "localhost" || host == "::1" || host.hasPrefix("127.")
        if isLoopback {
            return .loopback
        }

        let secureTLS = parsed.scheme?.lowercased() == "https"
        return .remote(secureTLS: secureTLS)
    }
}
