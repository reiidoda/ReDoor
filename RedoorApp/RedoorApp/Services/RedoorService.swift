import Foundation
import Combine
import Security

// --- Helper for C Strings ---

private func rustStringToString(_ ptr: UnsafeMutablePointer<CChar>?) -> String? {
    guard let ptr = ptr else { return nil }
    defer { redoor_free_string(ptr) }
    return String(cString: ptr)
}

// --- Data Models ---

struct RedoorIncomingMessage: Codable, Identifiable, Equatable {
    let id: String
    let timestamp: UInt64
    let sender: String
    let content: String
    let msg_type: String
    let group_id: String?
    let read: Bool
}

struct RedoorNetworkStatus: Codable {
    let relay_connected: Bool
    let blockchain_connected: Bool
}

struct OnionNodeConfig: Codable {
    let url: String
    let pub_key: String
    let operator_tag: String?
    let jurisdiction_tag: String?
    let asn_tag: String?
    
    enum CodingKeys: String, CodingKey {
        case url, pub_key
        case operator_tag = "operator_tag"
        case jurisdiction_tag = "jurisdiction_tag"
        case asn_tag = "asn_tag"
    }
    
    init(url: String, pub_key: String, operator_tag: String? = nil, jurisdiction_tag: String? = nil, asn_tag: String? = nil) {
        self.url = url
        self.pub_key = pub_key
        self.operator_tag = operator_tag
        self.jurisdiction_tag = jurisdiction_tag
        self.asn_tag = asn_tag
    }
}

enum NetworkConfigValidationError: LocalizedError, Equatable {
    case invalidRelayURL
    case unsupportedRelayScheme
    case relayHostMissing
    case insecureRemoteRelay
    case missingHmacForRemoteRelay
    case missingRelayPinForRemoteRelay
    case invalidBlockchainAddress
    case invalidRelaySPKIPin
    case invalidRelayCAB64
    case missingOnionNodeConfig
    case invalidOnionNodeConfig

    var errorDescription: String? {
        switch self {
        case .invalidRelayURL:
            return "Relay URL is invalid."
        case .unsupportedRelayScheme:
            return "Relay URL must use http:// or https://."
        case .relayHostMissing:
            return "Relay URL must include a host."
        case .insecureRemoteRelay:
            return "Use https:// for remote relay URLs. http:// is only allowed for localhost testing."
        case .missingHmacForRemoteRelay:
            return "HMAC key is required when connecting to a remote relay."
        case .missingRelayPinForRemoteRelay:
            return "Remote relay requires TLS pinning. Provide Relay SPKI pin or Relay CA pin."
        case .invalidBlockchainAddress:
            return "Blockchain address must be in host:port format."
        case .invalidRelaySPKIPin:
            return "Relay SPKI pin must be a Base64-encoded 32-byte SHA-256 hash."
        case .invalidRelayCAB64:
            return "Relay CA pin must be a valid Base64 DER certificate."
        case .missingOnionNodeConfig:
            return "Onion routing is mandatory. Provide at least 3 onion/mix nodes."
        case .invalidOnionNodeConfig:
            return "Onion node config is invalid. Expected JSON array with secure URLs and 32-byte hex pub_key values."
        }
    }
}

struct NetworkConfigValidator {
    static func validate(
        relayUrl: String,
        blockchainAddr: String,
        hmacKey: String?,
        relayCaB64: String? = nil,
        relaySpkiPinB64: String? = nil,
        onionNodesJSON: String? = nil
    ) -> NetworkConfigValidationError? {
        let trimmedRelay = relayUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let relayURL = URL(string: trimmedRelay) else { return .invalidRelayURL }
        guard let scheme = relayURL.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            return .unsupportedRelayScheme
        }
        guard let host = relayURL.host?.lowercased(), !host.isEmpty else { return .relayHostMissing }

        let isLoopbackHost = host == "localhost" || host == "::1" || host.hasPrefix("127.")
        if scheme == "http" && !isLoopbackHost {
            return .insecureRemoteRelay
        }

        let normalizedHmac = hmacKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        if !isLoopbackHost && (normalizedHmac == nil || normalizedHmac?.isEmpty == true) {
            return .missingHmacForRemoteRelay
        }

        let normalizedPin = relaySpkiPinB64?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedCa = relayCaB64?.trimmingCharacters(in: .whitespacesAndNewlines)
        if !isLoopbackHost
            && (normalizedPin == nil || normalizedPin?.isEmpty == true)
            && (normalizedCa == nil || normalizedCa?.isEmpty == true) {
            return .missingRelayPinForRemoteRelay
        }

        let trimmedBlockchain = blockchainAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedBlockchain.isEmpty, trimmedBlockchain.contains(":") else {
            return .invalidBlockchainAddress
        }

        if let pin = normalizedPin, !pin.isEmpty {
            guard let pinBytes = Data(base64Encoded: pin), pinBytes.count == 32 else {
                return .invalidRelaySPKIPin
            }
        }

        if let ca = normalizedCa, !ca.isEmpty {
            guard let caBytes = Data(base64Encoded: ca), !caBytes.isEmpty else {
                return .invalidRelayCAB64
            }
            let cert = SecCertificateCreateWithData(nil, caBytes as CFData)
            guard cert != nil else {
                return .invalidRelayCAB64
            }
        }

        let trimmedOnionNodes = onionNodesJSON?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmedOnionNodes.isEmpty else {
            return .missingOnionNodeConfig
        }
        guard let onionData = trimmedOnionNodes.data(using: .utf8),
              let onionNodes = try? JSONDecoder().decode([OnionNodeConfig].self, from: onionData),
              onionNodes.count >= 3 else {
            return .invalidOnionNodeConfig
        }
        
        // Use OnionNodesManager to validate
        guard OnionNodesManager.validateNodes(onionNodes) else {
            return .invalidOnionNodeConfig
        }

        return nil
    }
}

enum SessionBootstrapResult {
    case ready(peerId: String, safetyNumber: String?)
    case failed(reason: String)
}

// --- Onion Nodes Configuration Manager ---

struct OnionNodesManager {
    /// Default production onion/mix nodes with security details
    /// Each node includes:
    /// - url: Secure endpoint (https:// or .onion address)
    /// - pub_key: 32-byte curve25519 public key (64 hex chars)
    /// - operator_tag: Operator identifier for correlation resistance
    /// - jurisdiction_tag: Legal jurisdiction for diversification
    /// - asn_tag: AS number for network diversity
    static func defaultNodes() -> [OnionNodeConfig] {
        return [
            OnionNodeConfig(
                url: "https://mix1.redoor.net",
                pub_key: "1111111111111111111111111111111111111111111111111111111111111111",
                operator_tag: "operator-1",
                jurisdiction_tag: "US-CA",
                asn_tag: "AS15169"
            ),
            OnionNodeConfig(
                url: "https://mix2.redoor.net",
                pub_key: "2222222222222222222222222222222222222222222222222222222222222222",
                operator_tag: "operator-2",
                jurisdiction_tag: "EU-DE",
                asn_tag: "AS201505"
            ),
            OnionNodeConfig(
                url: "https://mix3.redoor.net",
                pub_key: "3333333333333333333333333333333333333333333333333333333333333333",
                operator_tag: "operator-3",
                jurisdiction_tag: "SG-SG",
                asn_tag: "AS3352"
            ),
            OnionNodeConfig(
                url: "https://mix4.redoor.net",
                pub_key: "4444444444444444444444444444444444444444444444444444444444444444",
                operator_tag: "operator-4",
                jurisdiction_tag: "CH-CH",
                asn_tag: "AS30853"
            ),
            OnionNodeConfig(
                url: "https://mix5.redoor.net",
                pub_key: "5555555555555555555555555555555555555555555555555555555555555555",
                operator_tag: "operator-5",
                jurisdiction_tag: "JP-JP",
                asn_tag: "AS2544"
            ),
            // Tor-based onion nodes for additional anonymity
            OnionNodeConfig(
                url: "https://mix1234567890abcdef1234567890abcd.onion",
                pub_key: "6666666666666666666666666666666666666666666666666666666666666666",
                operator_tag: "operator-tor-1",
                jurisdiction_tag: "ISL-IS",
                asn_tag: "AS1659"
            ),
            OnionNodeConfig(
                url: "https://mixfedcba0987654321fedcba0987654321.onion",
                pub_key: "7777777777777777777777777777777777777777777777777777777777777777",
                operator_tag: "operator-tor-2",
                jurisdiction_tag: "NL-NL",
                asn_tag: "AS12389"
            ),
            OnionNodeConfig(
                url: "https://mixabcdef1234567890abcdef1234567890.onion",
                pub_key: "8888888888888888888888888888888888888888888888888888888888888888",
                operator_tag: "operator-tor-3",
                jurisdiction_tag: "NO-NO",
                asn_tag: "AS174"
            )
        ]
    }
    
    /// Generate default onion nodes JSON string with all security details
    static func defaultOnionNodesJSON() -> String {
        let nodes = defaultNodes()
        if let jsonData = try? JSONEncoder().encode(nodes),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            return jsonString
        }
        return "[]"
    }

    /// Always returns a valid onion-node JSON payload and shuffles node order
    /// to avoid deterministic path reuse across disconnect/reconnect cycles.
    static func autoCompleteOnionNodesJSON(previousJSON: String? = nil) -> String {
        var nodes = defaultNodes().shuffled()

        if let previousJSON,
           let data = previousJSON.data(using: .utf8),
           let previous = try? JSONDecoder().decode([OnionNodeConfig].self, from: data),
           previous.count >= 3 {
            let previousFirst = previous.first?.url
            if let first = nodes.first, first.url == previousFirst, nodes.count > 1 {
                nodes.swapAt(0, 1)
            }
        }

        guard validateNodes(nodes),
              let jsonData = try? JSONEncoder().encode(nodes),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            return defaultOnionNodesJSON()
        }

        return jsonString
    }
    
    /// Validate onion nodes configuration
    static func validateNodes(_ nodes: [OnionNodeConfig]) -> Bool {
        // Require at least 3 nodes for security
        guard nodes.count >= 3 else { return false }
        
        for node in nodes {
            // Validate URL is secure
            let url = node.url.lowercased()
            let isSecure = url.hasPrefix("https://") || url.hasPrefix("wss://")
            let isOnion = url.contains(".onion")
            let isLocalhost = url.contains("localhost") || url.contains("127.0.0.1")
            
            guard isSecure || isOnion || isLocalhost else {
                return false
            }
            
            // Validate pub_key is 32-byte hex
            let pubKey = node.pub_key.lowercased()
            let isValidHex = pubKey.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
            guard isValidHex else {
                return false
            }
        }
        
        return true
    }
}

// --- Microservices ---

/// Manages network configuration and connection to the Relay/Blockchain.
class NetworkService {
    func connect(
        relayUrl: String,
        blockchainAddr: String,
        hmacKey: String? = nil,
        relayCaB64: String? = nil,
        relaySpkiPinB64: String? = nil,
        onionNodesJSON: String? = nil
    ) -> Bool {
        guard RedoorFFI.shared.configureOnionRouting(nodesJSON: onionNodesJSON) else {
            return false
        }
        guard let onionStatus = RedoorFFI.shared.onionStatus(),
              onionStatus.enabled,
              onionStatus.nodeCount >= 3 else {
            return false
        }
        guard RedoorFFI.shared.setRelayCAB64(relayCaB64) else {
            return false
        }
        guard RedoorFFI.shared.setRelaySPKIPinB64(relaySpkiPinB64) else {
            return false
        }

        let res = relayUrl.withCString { r in
            blockchainAddr.withCString { b in
                if let hmac = hmacKey {
                    return hmac.withCString { h in
                        redoor_init_env(r, b, h)
                    }
                } else {
                    return redoor_init_env(r, b, nil)
                }
            }
        }
        return res == 0
    }
}

/// Manages local identity (keys).
class IdentityService {
    var profileProvider: () -> IdentitySecurityProfile = { .strictEphemeral }

    func create() -> String? {
        guard let id = rustStringToString(redoor_create_identity()) else { return nil }
        _ = rustStringToString(redoor_generate_prekeys())
        _ = persistIdentityIfAllowed()
        return id
    }

    func generatePrekeyBundle() -> String? {
        rustStringToString(redoor_generate_prekeys())
    }

    func current() -> String? {
        if let existing = rustStringToString(redoor_get_identity()), !existing.isEmpty {
            return existing
        }

        let profile = profileProvider()
        guard profile.allowsPersistentIdentityMaterial else {
            return nil
        }
        guard RedoorFFI.shared.loadKeyFromKeychain(profile: profile) else {
            return nil
        }
        return rustStringToString(redoor_get_identity())
    }

    @discardableResult
    func persistIdentityIfAllowed() -> Bool {
        let profile = profileProvider()
        guard profile.allowsPersistentIdentityMaterial else {
            return false
        }
        do {
            try RedoorFFI.shared.saveKeyToKeychain(profile: profile)
            return true
        } catch {
            return false
        }
    }

    func clearPersistentIdentityMaterial(profile: IdentitySecurityProfile) {
        RedoorFFI.shared.deleteKeyFromKeychain(profile: profile)
    }
}

/// Handles sending and receiving encrypted messages.
class MessagingService {
    func send(to peerId: String, message: String) -> Bool {
        let res = peerId.withCString { p in
            message.withCString { m in
                redoor_send_message(p, m)
            }
        }
        return res == 0
    }

    func poll() -> [RedoorIncomingMessage] {
        guard let jsonStr = rustStringToString(redoor_poll_messages()) else { return [] }
        guard let data = jsonStr.data(using: .utf8) else { return [] }
        do {
            let decoded = try JSONDecoder().decode([RedoorIncomingMessage].self, from: data)
            // Message-only scope: ignore non-text payloads.
            return decoded.filter { msg in
                msg.msg_type.isEmpty || msg.msg_type == "text"
            }
        } catch {
            print("RedoorService: Failed to decode messages: \(error)")
            return []
        }
    }

    @discardableResult
    func consume(peerId: String, messageId: String) -> Bool {
        RedoorFFI.shared.consumeMessage(peerID: peerId, messageID: messageId)
    }
}

/// Manages X3DH sessions and handshakes.
class SessionService {
    func connectWithBundle(bundleJson: String) -> String? {
        return bundleJson.withCString { b in
            rustStringToString(redoor_connect_via_qr(b))
        }
    }

    func hasSession(with peerId: String) -> Bool {
        let rc = peerId.withCString { p in
            redoor_has_session(p)
        }
        return rc == 1
    }

    func safetyNumber(for peerId: String) -> String? {
        return peerId.withCString { p in
            rustStringToString(redoor_get_safety_number(p))
        }
    }
}

/// Handles critical security operations like memory wiping.
class SecurityService {
    var onDuress: (() -> Void)?

    func wipeMemory() {
        redoor_wipe_memory()
    }

    func enterDuressMode() {
        _ = redoor_enter_duress_mode()
        onDuress?()
    }
}

// --- Main Service Wrapper ---

class RedoorService: ObservableObject {
    static let defaultRelayURL = "https://localhost:8443"
    static let defaultBlockchainAddr = "127.0.0.1:9444"
    static let defaultOnionNodesJSON = ProcessInfo.processInfo.environment["REDOOR_ONION_NODES_JSON"] ?? OnionNodesManager.defaultOnionNodesJSON()
    private static let fixedPollingIntervalMs: UInt64 = 1000
    private static let localMessageLifetimeSec: TimeInterval = 15

    static let shared = RedoorService()
    @Published var isDuressMode = false
    @Published var isConnected = false
    @Published var isBlockchainConnected = false
    @Published var isLocked = false
    @Published var lastSecurityError: String?
    @Published var messages: [RedoorIncomingMessage] = []
    @Published private(set) var identityProfile: IdentitySecurityProfile = .current
    @Published private(set) var pqHandshakePolicy: PQHandshakePolicy = .current
    @Published private(set) var lockdownProfile: LockdownCompatibilityProfile = .current
    @Published private(set) var lockdownStatus: LockdownCompatibilityStatus =
        .initial(profile: .current)

    // Connection targets for retry logic
    private var targetRelayUrl: String?
    private var targetBlockchainAddr: String?
    private var targetRelayCaB64: String?
    private var targetRelaySpkiPinB64: String?
    private var targetOnionNodesJSON: String?

    let network = NetworkService()
    let identity = IdentityService()
    let messaging = MessagingService()
    let session = SessionService()
    let security = SecurityService()
    let heartbeat = HeartbeatManager()

    private var messagePollTimer: AnyCancellable?
    private var statusPollTimer: AnyCancellable?
    private var cancellables = Set<AnyCancellable>()
    private var reconnectAttempts: Int = 0
    private var reconnectWorkItem: DispatchWorkItem?
    private var heartbeatEnabledByUser: Bool = true
    private var messagePurgeTasks: [String: DispatchWorkItem] = [:]
    private var strictAnonymityEnforced = false
    private var fixedPollingEnforced = false
    private var constantRateEnforced = false

    private init() {
        identity.profileProvider = { [weak self] in
            self?.identityProfile ?? .strictEphemeral
        }

        security.onDuress = { [weak self] in
            DispatchQueue.main.async {
                self?.isDuressMode = true
                // Stop retrying in duress
                self?.targetRelayUrl = nil
                self?.targetBlockchainAddr = nil
                self?.targetRelayCaB64 = nil
                self?.targetRelaySpkiPinB64 = nil
                self?.targetOnionNodesJSON = nil
                self?.reconnectAttempts = 0
                self?.reconnectWorkItem?.cancel()
                self?.reconnectWorkItem = nil
                self?.heartbeat.stop()
                _ = redoor_enable_fixed_polling(0)
                self?.messagePollTimer?.cancel()
                self?.statusPollTimer?.cancel()
                self?.security.wipeMemory()
                SecureStorage.clearAll()
                if let profile = self?.identityProfile {
                    self?.identity.clearPersistentIdentityMaterial(profile: profile)
                }
                self?.cancelMessagePurgeTasks()
                self?.messages.removeAll()
                self?.isConnected = false
                self?.isBlockchainConnected = false
                self?.isLocked = true
            }
        }

        // Configure heartbeat to send dummy traffic
        heartbeat.sendPacketHandler = { [weak self] packet in
            guard let self = self else { return }
            // Only send heartbeat if connected and not locked
            if self.isConnected && !self.isLocked {
                // In a real implementation, this would call a specific FFI function for cover traffic.
                // For now, we simulate it or send it to a "dummy" peer if supported.
                print("RedoorService: Sending heartbeat packet (\(packet.count) bytes)")
            }
        }

        // Poll for messages every second
        messagePollTimer = Timer.publish(every: 1.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.pollMessages()
            }

        // Poll network status independently to keep UI state fresh and drive retry behavior.
        statusPollTimer = Timer.publish(every: 3.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.updateConnectionStatus()
            }

        lockdownStatus = evaluateLockdownCompatibility()
        if !RedoorFFI.shared.setPqHandshakePolicy(pqHandshakePolicy.rawValue) {
            lastSecurityError = "Failed to set initial PQ handshake policy."
        }
    }

    func pollMessages() {
        guard !isLocked, !isDuressMode, isConnected else { return }
        let newMessages = messaging.poll()
        if !newMessages.isEmpty {
            // Avoid duplicates
            let existingIDs = Set(messages.map { $0.id })
            let uniqueNewMessages = newMessages.filter { !existingIDs.contains($0.id) }
            if !uniqueNewMessages.isEmpty {
                messages.append(contentsOf: uniqueNewMessages)
                messages.sort { $0.timestamp < $1.timestamp }
                for message in uniqueNewMessages {
                    _ = messaging.consume(peerId: message.sender, messageId: message.id)
                    scheduleMessagePurge(for: message.id)
                }
            }
        }
    }

    @discardableResult
    func connect(
        relayUrl: String,
        blockchainAddr: String,
        hmacKey: String? = nil,
        relayCaB64: String? = nil,
        relaySpkiPinB64: String? = nil,
        onionNodesJSON: String? = nil
    ) -> Bool {
        let trimmedRelay = relayUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedBlockchain = blockchainAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedHmac = hmacKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedRelayCaB64 = relayCaB64?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedRelaySpkiPinB64 = relaySpkiPinB64?.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedOnionNodesJSON = onionNodesJSON?.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedHmac: String?
        if !HMACKeyStore.save(normalizedHmac) {
            DispatchQueue.main.async {
                self.lastSecurityError = "Failed to securely store HMAC key in volatile memory."
                self.isConnected = false
                self.isBlockchainConnected = false
            }
            heartbeat.stop()
            return false
        }
        resolvedHmac = HMACKeyStore.load()
        let effectiveOnionNodesJSON: String?
        if let provided = normalizedOnionNodesJSON, !provided.isEmpty {
            effectiveOnionNodesJSON = provided
        } else {
            effectiveOnionNodesJSON = targetOnionNodesJSON
        }

        if let validationError = NetworkConfigValidator.validate(
            relayUrl: trimmedRelay,
            blockchainAddr: trimmedBlockchain,
            hmacKey: normalizedHmac,
            relayCaB64: normalizedRelayCaB64,
            relaySpkiPinB64: normalizedRelaySpkiPinB64,
            onionNodesJSON: effectiveOnionNodesJSON
        ) {
            DispatchQueue.main.async {
                self.lastSecurityError = validationError.localizedDescription
                self.isConnected = false
                self.isBlockchainConnected = false
            }
            heartbeat.stop()
            return false
        }

        guard RedoorFFI.shared.setPqHandshakePolicy(pqHandshakePolicy.rawValue) else {
            DispatchQueue.main.async {
                self.lastSecurityError = "Failed to apply PQ handshake policy."
                self.isConnected = false
                self.isBlockchainConnected = false
            }
            heartbeat.stop()
            return false
        }

        targetRelayUrl = trimmedRelay
        targetBlockchainAddr = trimmedBlockchain
        targetRelayCaB64 = normalizedRelayCaB64
        targetRelaySpkiPinB64 = normalizedRelaySpkiPinB64
        targetOnionNodesJSON = effectiveOnionNodesJSON
        strictAnonymityEnforced = false
        fixedPollingEnforced = false
        constantRateEnforced = false

        let didConnect = network.connect(
            relayUrl: trimmedRelay,
            blockchainAddr: trimmedBlockchain,
            hmacKey: resolvedHmac,
            relayCaB64: normalizedRelayCaB64,
            relaySpkiPinB64: normalizedRelaySpkiPinB64,
            onionNodesJSON: effectiveOnionNodesJSON
        )
        if didConnect {
            strictAnonymityEnforced = redoor_enable_strict_anonymity(1) == 0
            guard strictAnonymityEnforced else {
                DispatchQueue.main.async {
                    self.lastSecurityError = "Failed to enforce strict anonymity policy."
                    self.isConnected = false
                }
                return false
            }

            fixedPollingEnforced = redoor_enable_fixed_polling(Self.fixedPollingIntervalMs) == 0
            guard fixedPollingEnforced else {
                DispatchQueue.main.async {
                    self.lastSecurityError = "Failed to start fixed relay polling."
                    self.isConnected = false
                }
                return false
            }

            // Strict anonymity wiring in the Rust runtime starts the constant-rate loop.
            constantRateEnforced = true

            let status = evaluateLockdownCompatibility()
            if lockdownProfile.requiresFailClosed && !status.isCompatible {
                let reasons = status.violations.joined(separator: " ")
                DispatchQueue.main.async {
                    self.lastSecurityError = "Lockdown strict profile blocked connection. \(reasons)"
                }
                disconnect()
                return false
            }

            print("RedoorService: Connected successfully")
            reconnectAttempts = 0
            reconnectWorkItem?.cancel()
            reconnectWorkItem = nil
            DispatchQueue.main.async {
                self.lastSecurityError = nil
            }
            if heartbeatEnabledByUser && !heartbeat.isHeartbeating {
                heartbeat.start()
            }
        } else {
            print("RedoorService: Failed to connect")
            DispatchQueue.main.async {
                self.lastSecurityError = "Failed to apply onion routing/TLS pinning or connect to relay."
            }
            strictAnonymityEnforced = false
            fixedPollingEnforced = false
            constantRateEnforced = false
            heartbeat.stop()
        }
        _ = evaluateLockdownCompatibility()
        updateConnectionStatus()
        return didConnect
    }

    func disconnect() {
        _ = redoor_enable_fixed_polling(0)
        strictAnonymityEnforced = false
        fixedPollingEnforced = false
        constantRateEnforced = false
        targetRelayUrl = nil
        targetBlockchainAddr = nil
        targetRelayCaB64 = nil
        targetRelaySpkiPinB64 = nil
        targetOnionNodesJSON = nil
        reconnectAttempts = 0
        reconnectWorkItem?.cancel()
        reconnectWorkItem = nil
        heartbeat.stop()
        security.wipeMemory()
        SecureStorage.clearAll()
        cancelMessagePurgeTasks()
        DispatchQueue.main.async {
            self.messages.removeAll()
            self.isConnected = false
            self.isBlockchainConnected = false
        }
        _ = evaluateLockdownCompatibility()
    }

    func lock(clearPersistentIdentity: Bool = false) {
        disconnect()
        if clearPersistentIdentity {
            identity.clearPersistentIdentityMaterial(profile: identityProfile)
        }
        DispatchQueue.main.async {
            self.isLocked = true
        }
    }

    func unlock() {
        DispatchQueue.main.async {
            self.isLocked = false
        }
    }

    private func scheduleMessagePurge(for messageID: String) {
        guard messagePurgeTasks[messageID] == nil else { return }

        let task = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            self.messages.removeAll { $0.id == messageID }
            self.messagePurgeTasks.removeValue(forKey: messageID)
        }
        messagePurgeTasks[messageID] = task
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.localMessageLifetimeSec, execute: task)
    }

    private func cancelMessagePurgeTasks() {
        for task in messagePurgeTasks.values {
            task.cancel()
        }
        messagePurgeTasks.removeAll()
    }

    func updateConnectionStatus() {
        guard let jsonStr = rustStringToString(redoor_get_network_status()) else { return }
        guard let data = jsonStr.data(using: .utf8) else { return }
        do {
            let status = try JSONDecoder().decode(RedoorNetworkStatus.self, from: data)
            DispatchQueue.main.async {
                self.isConnected = status.relay_connected
                self.isBlockchainConnected = status.blockchain_connected
            }
            _ = evaluateLockdownCompatibility()

            // Retry mechanism: If we expect to be connected but aren't, try again.
            if !status.relay_connected && !self.isDuressMode, targetRelayUrl != nil, targetBlockchainAddr != nil {
                guard reconnectWorkItem == nil else { return }

                let delay = min(30.0, pow(2.0, Double(reconnectAttempts)))
                reconnectAttempts += 1
                print("RedoorService: Connection lost. Scheduling retry in \(Int(delay))s...")

                let workItem = DispatchWorkItem { [weak self] in
                    guard let self = self else { return }
                    self.reconnectWorkItem = nil
                    guard !self.isDuressMode,
                          let targetRelay = self.targetRelayUrl,
                          let targetChain = self.targetBlockchainAddr else {
                        return
                    }
                    print("RedoorService: Attempting reconnect now...")
                    _ = self.connect(
                        relayUrl: targetRelay,
                        blockchainAddr: targetChain,
                        hmacKey: HMACKeyStore.load(),
                        relayCaB64: self.targetRelayCaB64,
                        relaySpkiPinB64: self.targetRelaySpkiPinB64,
                        onionNodesJSON: self.targetOnionNodesJSON
                    )
                }

                reconnectWorkItem = workItem
                DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
            } else if status.relay_connected {
                // Ensure heartbeat is running if connected
                reconnectAttempts = 0
                reconnectWorkItem?.cancel()
                reconnectWorkItem = nil
                if heartbeatEnabledByUser && !heartbeat.isHeartbeating {
                    heartbeat.start()
                }
            }
        } catch {
            print("RedoorService: Failed to decode network status")
        }
    }

    func toggleHeartbeat() {
        setHeartbeatEnabled(!heartbeat.isHeartbeating)
    }

    func setHeartbeatEnabled(_ enabled: Bool) {
        heartbeatEnabledByUser = enabled
        if enabled {
            if isConnected && !heartbeat.isHeartbeating {
                heartbeat.start()
            }
        } else {
            heartbeat.stop()
        }
        let status = evaluateLockdownCompatibility()
        if lockdownProfile.requiresFailClosed && isConnected && !status.isCompatible {
            lastSecurityError = "Lockdown strict profile requires cover heartbeat. Disconnecting."
            disconnect()
        }
    }

    func setHeartbeatInterval(_ interval: Double) {
        heartbeat.meanInterval = interval
        if heartbeat.isHeartbeating {
            heartbeat.start()
        }
    }

    func setIdentityProfile(_ profile: IdentitySecurityProfile) {
        guard identityProfile != profile else { return }

        let previous = identityProfile
        identityProfile = profile

        if previous.allowsPersistentIdentityMaterial && !profile.allowsPersistentIdentityMaterial {
            identity.clearPersistentIdentityMaterial(profile: previous)
        }
        let status = evaluateLockdownCompatibility()
        if lockdownProfile.requiresFailClosed && isConnected && !status.isCompatible {
            lastSecurityError = "Lockdown strict profile rejected updated identity profile."
            disconnect()
        }
    }

    func setLockdownProfile(_ profile: LockdownCompatibilityProfile) {
        guard lockdownProfile != profile else { return }
        lockdownProfile = profile
        let status = evaluateLockdownCompatibility()
        if lockdownProfile.requiresFailClosed && isConnected && !status.isCompatible {
            lastSecurityError = "Lockdown strict profile blocked current runtime settings."
            disconnect()
        }
    }

    func setPqHandshakePolicy(_ policy: PQHandshakePolicy) {
        guard pqHandshakePolicy != policy else { return }
        guard RedoorFFI.shared.setPqHandshakePolicy(policy.rawValue) else {
            lastSecurityError = "Failed to update PQ handshake policy."
            return
        }
        pqHandshakePolicy = policy
        let status = evaluateLockdownCompatibility()
        if lockdownProfile.requiresFailClosed && isConnected && !status.isCompatible {
            lastSecurityError = "Lockdown strict profile requires stronger PQ handshake policy."
            disconnect()
        }
    }

    @discardableResult
    private func evaluateLockdownCompatibility() -> LockdownCompatibilityStatus {
        let snapshot = LockdownCompatibilitySnapshot(
            profile: lockdownProfile,
            identityProfile: identityProfile,
            pqHandshakePolicy: pqHandshakePolicy,
            relayURL: targetRelayUrl,
            hmacKeyPresent: !(HMACKeyStore.load()?.isEmpty ?? true),
            relaySPKIPinConfigured: !(targetRelaySpkiPinB64?.isEmpty ?? true),
            relayCAPinConfigured: !(targetRelayCaB64?.isEmpty ?? true),
            onionRoutingConfigured: !(targetOnionNodesJSON?.isEmpty ?? true),
            strictAnonymityEnforced: strictAnonymityEnforced,
            fixedPollingEnforced: fixedPollingEnforced,
            constantRateEnforced: constantRateEnforced,
            coverHeartbeatEnabled: heartbeatEnabledByUser,
            networkConfigured: targetRelayUrl != nil && targetBlockchainAddr != nil
        )
        let status = LockdownCompatibilityEvaluator.evaluate(snapshot: snapshot)
        lockdownStatus = status
        return status
    }

    func ensureSession(for peerDescriptor: String) -> SessionBootstrapResult {
        let input = peerDescriptor.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else {
            return .failed(reason: "Peer input is empty.")
        }

        if session.hasSession(with: input) {
            return .ready(peerId: input, safetyNumber: session.safetyNumber(for: input))
        }

        guard let peerIdFromBundle = Self.extractPeerId(fromBundleJSON: input) else {
            if Self.looksLikeIdentityKey(input) {
                return .failed(reason: "This looks like a raw identity key. For first-time connection, paste the peer Connection ID (the full prekey bundle JSON).")
            }
            return .failed(reason: "No session for this peer. Paste a peer Connection ID (prekey bundle JSON) or use an existing peer ID with a cached session.")
        }

        if session.connectWithBundle(bundleJson: input) == nil {
            return .failed(reason: "Failed to establish session from bundle.")
        }

        if session.hasSession(with: peerIdFromBundle) {
            return .ready(peerId: peerIdFromBundle, safetyNumber: session.safetyNumber(for: peerIdFromBundle))
        }

        return .failed(reason: "Session was not created.")
    }

    private static func looksLikeIdentityKey(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let isHexIdentity = trimmed.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil
        if isHexIdentity {
            return true
        }

        // Accept common base64 lengths for 32-byte identity material.
        let isLikelyBase64Identity = trimmed.range(of: "^[A-Za-z0-9+/]{42,44}={0,2}$", options: .regularExpression) != nil
        return isLikelyBase64Identity
    }

    private static func extractPeerId(fromBundleJSON raw: String) -> String? {
        guard let data = raw.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let keyValue = json["identity_key"] else {
            return nil
        }

        if let key = keyValue as? String, !key.isEmpty {
            return key
        }

        if let bytes = keyValue as? [UInt8], !bytes.isEmpty {
            return bytes.map { String(format: "%02x", $0) }.joined()
        }

        return nil
    }
}
