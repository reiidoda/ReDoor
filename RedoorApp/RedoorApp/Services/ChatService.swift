import Foundation
import Combine
import UIKit

protocol ChatServiceProviding: AnyObject {
    var messagesPublisher: AnyPublisher<[RedoorIncomingMessage], Never> { get }
    var isConnectedPublisher: AnyPublisher<Bool, Never> { get }
    var lastErrorPublisher: AnyPublisher<String?, Never> { get }
    var lastError: String? { get }

    @discardableResult
    func setupEnvironment(
        relayUrl: String?,
        blockchainAddr: String?,
        hmacKey: String?,
        relayCaB64: String?,
        relaySpkiPinB64: String?,
        onionNodesJSON: String?
    ) -> Bool

    func createIdentity() -> String?
    func createIdentity(
        relayUrl: String,
        blockchainAddr: String,
        hmacKey: String?,
        relayCaB64: String?,
        relaySpkiPinB64: String?,
        onionNodesJSON: String?
    ) -> String?
    func getIdentity() -> String?
    func generatePrekeyBundle() -> String?

    @discardableResult
    func connect(to peerDescriptor: String) -> (success: Bool, peerId: String?, safetyNumber: String?)

    @discardableResult
    func sendMessage(to peerID: String, text: String) -> Bool

    func setHeartbeatEnabled(_ enabled: Bool)
    func setHeartbeatInterval(_ interval: TimeInterval)
}

// Wrapper around RedoorService to provide a cleaner API for ViewModels
class ChatService: ObservableObject, ChatServiceProviding {
    static let shared = ChatService()
    private let redoor = RedoorService.shared
    
    @Published var messages: [RedoorIncomingMessage] = []
    @Published var isConnected: Bool = false
    @Published var lastError: String?
    
    private var cancellables = Set<AnyCancellable>()

    #if targetEnvironment(simulator)
    private let shouldAutoLockOnLifecycle = false
    #else
    private let shouldAutoLockOnLifecycle = ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] == nil
    #endif

    var messagesPublisher: AnyPublisher<[RedoorIncomingMessage], Never> {
        $messages.eraseToAnyPublisher()
    }

    var isConnectedPublisher: AnyPublisher<Bool, Never> {
        $isConnected.eraseToAnyPublisher()
    }

    var lastErrorPublisher: AnyPublisher<String?, Never> {
        $lastError.eraseToAnyPublisher()
    }
    
    init() {
        redoor.$messages
            .assign(to: \.messages, on: self)
            .store(in: &cancellables)

        redoor.$isConnected
            .assign(to: \.isConnected, on: self)
            .store(in: &cancellables)
            
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appWillTerminate),
            name: UIApplication.willTerminateNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appWillResignActive),
            name: UIApplication.willResignActiveNotification,
            object: nil
        )
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    @objc private func appDidEnterBackground() {
        guard shouldAutoLockOnLifecycle else {
            print("App backgrounded: keeping session active for simulator/testing flow")
            return
        }
        print("App backgrounded: Locking app...")
        redoor.lock()
    }

    @objc private func appWillTerminate() {
        print("App terminating: Wiping in-memory state...")
        redoor.lock()
    }

    @objc private func appWillResignActive() {
        guard shouldAutoLockOnLifecycle else {
            print("App resigning active: keeping session active for simulator/testing flow")
            return
        }
        print("App resigning active: Locking app...")
        redoor.lock()
    }
    
    var isHeartbeating: Bool {
        redoor.heartbeat.isHeartbeating
    }

    @discardableResult
    func setupEnvironment(
        relayUrl: String? = nil,
        blockchainAddr: String? = nil,
        hmacKey: String? = nil,
        relayCaB64: String? = nil,
        relaySpkiPinB64: String? = nil,
        onionNodesJSON: String? = nil
    ) -> Bool {
        let finalRelayUrl = relayUrl ?? RedoorService.defaultRelayURL
        let finalBlockchainAddr = blockchainAddr ?? RedoorService.defaultBlockchainAddr
        let providedHmac = hmacKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        let finalHmacKey = (providedHmac?.isEmpty == false) ? providedHmac : nil
        let finalRelayCaB64 = relayCaB64
        let finalRelaySpkiPinB64 = relaySpkiPinB64
        let finalOnionNodesJSON = onionNodesJSON
        
        print("🌐 [ChatService.setupEnvironment] Relay: \(finalRelayUrl)")
        print("🌐 [ChatService.setupEnvironment] Blockchain: \(finalBlockchainAddr)")
        print("🌐 [ChatService.setupEnvironment] OnionNodes: \(finalOnionNodesJSON?.prefix(50) ?? "nil")...")

        let didApply = redoor.connect(
            relayUrl: finalRelayUrl,
            blockchainAddr: finalBlockchainAddr,
            hmacKey: finalHmacKey,
            relayCaB64: finalRelayCaB64,
            relaySpkiPinB64: finalRelaySpkiPinB64,
            onionNodesJSON: finalOnionNodesJSON
        )
        if didApply {
            print("✅ [ChatService.setupEnvironment] Environment setup succeeded")
            lastError = nil
        } else {
            let error = redoor.lastSecurityError ?? "Invalid network security configuration."
            print("❌ [ChatService.setupEnvironment] Environment setup failed: \(error)")
            lastError = error
        }
        return didApply
    }
    
    func createIdentity() -> String? {
        print("📱 [ChatService] createIdentity() called")
        let identity = redoor.identity.create()
        if let id = identity {
            print("✅ [ChatService] Identity created: \(id.prefix(30))...")
            lastError = nil
        } else {
            print("❌ [ChatService] redoor.identity.create() returned nil")
            lastError = "Failed to create local identity."
        }
        return identity
    }

    func createIdentity(
        relayUrl: String,
        blockchainAddr: String,
        hmacKey: String? = nil,
        relayCaB64: String? = nil,
        relaySpkiPinB64: String? = nil,
        onionNodesJSON: String? = nil
    ) -> String? {
        print("📱 [ChatService] createIdentity(with config) called")
        // Identity generation is local-only and should not block on network availability.
        // Network environment is validated/applied during connect().
        return createIdentity()
    }
    
    func getIdentity() -> String? {
        return redoor.identity.current()
    }

    func generatePrekeyBundle() -> String? {
        return redoor.identity.generatePrekeyBundle()
    }
    
    @discardableResult
    func connect(to peerDescriptor: String) -> (success: Bool, peerId: String?, safetyNumber: String?) {
        switch redoor.ensureSession(for: peerDescriptor) {
        case .ready(let peerId, let safety):
            lastError = nil
            return (true, peerId, safety)
        case .failed(let reason):
            lastError = reason
            return (false, nil, nil)
        }
    }
    
    @discardableResult
    func sendMessage(to peerID: String, text: String) -> Bool {
        let ok = redoor.messaging.send(to: peerID, message: text)
        if !ok {
            lastError = "Send failed. Make sure a secure session exists."
        }
        return ok
    }
    
    func setHeartbeatEnabled(_ enabled: Bool) {
        redoor.setHeartbeatEnabled(enabled)
    }
    
    func toggleHeartbeat() {
        redoor.toggleHeartbeat()
    }
    
    func setHeartbeatInterval(_ interval: TimeInterval) {
        redoor.setHeartbeatInterval(interval)
    }
    
    func getSafetyNumber(for peerID: String) -> String? {
        return redoor.session.safetyNumber(for: peerID)
    }
}
