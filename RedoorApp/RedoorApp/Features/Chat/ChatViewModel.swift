import Foundation
import Combine
import UIKit

class ChatViewModel: ObservableObject {
    @Published var messageText: String = ""
    @Published var messages: [RedoorIncomingMessage] = []
    @Published var peerID: String = "" {
        didSet {
            if oldValue != peerID {
                isSessionReady = false
                safetyNumber = nil
            }
        }
    }
    @Published var myIdentity: String = ""
    @Published var myPrekeyBundle: String = ""
    @Published var isConnected: Bool = false
    @Published var isSessionReady: Bool = false
    @Published var safetyNumber: String?
    @Published var statusMessage: String?
    @Published var isGeneratingIdentity: Bool = false

    // Network configuration (internal only, not user-modifiable)
    private let relayUrl: String = RedoorService.defaultRelayURL
    private let blockchainAddr: String = RedoorService.defaultBlockchainAddr
    private let hmacKey: String = ""
    private let relayCaB64: String = ""
    private let relaySpkiPinB64: String = ""
    private var onionNodesJSON: String = OnionNodesManager.autoCompleteOnionNodesJSON()

    // Mandatory Security Features (always enabled, no user control)
    private let heartbeatEnabled: Bool = true
    private let heartbeatInterval: Double = 1.0
    private let anonymityModeEnabled: Bool = true
    private let coverTrafficEnabled: Bool = true

    private let chatService: ChatServiceProviding
    private let redoor: RedoorService
    private var cancellables = Set<AnyCancellable>()

    init(chatService: ChatServiceProviding = ChatService.shared, redoor: RedoorService = RedoorService.shared) {
        self.chatService = chatService
        self.redoor = redoor

        chatService.messagesPublisher
            .assign(to: \.messages, on: self)
            .store(in: &cancellables)

        chatService.isConnectedPublisher
            .sink { [weak self] connected in
                self?.isConnected = connected
                if !connected {
                    self?.isSessionReady = false
                    self?.safetyNumber = nil
                    self?.refreshSecurityConfigAfterDisconnect()
                }
            }
            .store(in: &cancellables)

        chatService.lastErrorPublisher
            .assign(to: \.statusMessage, on: self)
            .store(in: &cancellables)

        redoor.$isLocked
            .sink { [weak self] locked in
                guard let self = self, locked else { return }
                self.peerID = ""
                self.messageText = ""
                self.isSessionReady = false
                self.safetyNumber = nil
                self.myIdentity = ""
                self.isGeneratingIdentity = false
                self.statusMessage = "App locked. Unlock to continue."
            }
            .store(in: &cancellables)

        redoor.$isDuressMode
            .removeDuplicates()
            .sink { [weak self] duress in
                guard let self = self, duress else { return }
                self.peerID = ""
                self.messageText = ""
                self.isSessionReady = false
                self.safetyNumber = nil
                self.myIdentity = ""
                self.isGeneratingIdentity = false
                self.statusMessage = "Duress mode activated. Sensitive data wiped."
            }
            .store(in: &cancellables)

        if let id = chatService.getIdentity() {
            myIdentity = id
            refreshPrekeyBundle()
        }

        // Force mandatory security settings on startup
        chatService.setHeartbeatInterval(heartbeatInterval)
        chatService.setHeartbeatEnabled(true)
    }

    func createIdentity() {
        guard !isGeneratingIdentity else { return }
        isGeneratingIdentity = true
        statusMessage = "Generating identity..."
        print("🔐 [CreateIdentity] Starting identity creation process...")
        onionNodesJSON = OnionNodesManager.autoCompleteOnionNodesJSON(previousJSON: onionNodesJSON)

        let resolvedOnion = onionNodesJSON
        let resolvedHmac = hmacKey.isEmpty ? nil : hmacKey
        let resolvedRelayCa = relayCaB64.isEmpty ? nil : relayCaB64
        let resolvedRelaySpki = relaySpkiPinB64.isEmpty ? nil : relaySpkiPinB64

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let id = self.chatService.createIdentity(
                relayUrl: self.relayUrl,
                blockchainAddr: self.blockchainAddr,
                hmacKey: resolvedHmac,
                relayCaB64: resolvedRelayCa,
                relaySpkiPinB64: resolvedRelaySpki,
                onionNodesJSON: resolvedOnion.isEmpty ? nil : resolvedOnion
            )

            let generatedBundle = self.chatService.generatePrekeyBundle()
            let error = self.chatService.lastError ?? "Failed to create identity."

            DispatchQueue.main.async {
                self.isGeneratingIdentity = false

                if let id {
                    print("✅ [CreateIdentity] Identity created successfully: \(id.prefix(20))...")
                    self.myIdentity = id
                    if let generatedBundle, !generatedBundle.isEmpty {
                        self.myPrekeyBundle = generatedBundle
                    } else {
                        self.refreshPrekeyBundle()
                    }
                    self.statusMessage = "Identity created. Share your Connection ID with peers."
                    self.isSessionReady = false
                } else {
                    print("❌ [CreateIdentity] Identity creation failed: \(error)")
                    self.statusMessage = error
                }
            }
        }
    }

    func connect() {
        let trimmedPeer = peerID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPeer.isEmpty else {
            statusMessage = "Enter a peer Connection ID or an existing peer ID."
            return
        }
        peerID = trimmedPeer

        print("🔐 [Connect] Connecting to peer: \(trimmedPeer.prefix(40))...")
        onionNodesJSON = OnionNodesManager.autoCompleteOnionNodesJSON(previousJSON: onionNodesJSON)

        guard chatService.setupEnvironment(
            relayUrl: relayUrl,
            blockchainAddr: blockchainAddr,
            hmacKey: hmacKey.isEmpty ? nil : hmacKey,
            relayCaB64: relayCaB64.isEmpty ? nil : relayCaB64,
            relaySpkiPinB64: relaySpkiPinB64.isEmpty ? nil : relaySpkiPinB64,
            onionNodesJSON: onionNodesJSON.isEmpty ? nil : onionNodesJSON
        ) else {
            let error = chatService.lastError ?? "Invalid network security configuration."
            print("❌ [Connect] setupEnvironment failed: \(error)")
            statusMessage = error
            isSessionReady = false
            return
        }
        
        let result = chatService.connect(to: peerID)
        if result.success {
            if let resolvedPeer = result.peerId {
                peerID = resolvedPeer
            }
            safetyNumber = result.safetyNumber
            statusMessage = "Secure session ready."
            print("✅ [Connect] Session established. Safety #: \(result.safetyNumber ?? "N/A")")
            isSessionReady = true
        } else {
            let error = (chatService.lastError ?? "Failed to establish session.") + " Use the peer Connection ID from the Share section for first-time setup."
            print("❌ [Connect] Connection failed: \(error)")
            statusMessage = error
            isSessionReady = false
        }
    }

    func sendMessage() {
        let trimmedMessage = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedMessage.isEmpty else { return }
        let trimmedPeer = peerID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedPeer.isEmpty else {
            statusMessage = "Peer ID is required."
            return
        }
        peerID = trimmedPeer
        guard isSessionReady else {
            statusMessage = "Secure session not ready."
            return
        }
        guard chatService.sendMessage(to: peerID, text: trimmedMessage) else {
            statusMessage = chatService.lastError ?? "Failed to send message."
            return
        }
        statusMessage = nil
        messageText = ""
    }

    private func refreshSecurityConfigAfterDisconnect() {
        onionNodesJSON = OnionNodesManager.autoCompleteOnionNodesJSON(previousJSON: onionNodesJSON)
        print("🔄 [Security] Refreshed onion-node security config after disconnect")
    }

    func refreshPrekeyBundle() {
        if let bundle = chatService.generatePrekeyBundle(), !bundle.isEmpty {
            myPrekeyBundle = bundle
        }
    }
}
