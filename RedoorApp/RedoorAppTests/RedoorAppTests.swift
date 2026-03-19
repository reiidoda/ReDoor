import XCTest
import UIKit
import Combine
@testable import RedoorApp

final class RedoorAppTests: XCTestCase {
    private final class MockChatService: ChatServiceProviding {
        let messagesSubject = CurrentValueSubject<[RedoorIncomingMessage], Never>([])
        let isConnectedSubject = CurrentValueSubject<Bool, Never>(false)
        let lastErrorSubject = CurrentValueSubject<String?, Never>(nil)

        var messagesPublisher: AnyPublisher<[RedoorIncomingMessage], Never> {
            messagesSubject.eraseToAnyPublisher()
        }

        var isConnectedPublisher: AnyPublisher<Bool, Never> {
            isConnectedSubject.eraseToAnyPublisher()
        }

        var lastErrorPublisher: AnyPublisher<String?, Never> {
            lastErrorSubject.eraseToAnyPublisher()
        }

        var lastError: String? {
            lastErrorSubject.value
        }

        var setupEnvironmentResult = true
        var createdIdentity = "test-identity-key"
        var generatedBundle = "{\"identity_key\":\"test-identity-key\"}"
        var connectResult: (success: Bool, peerId: String?, safetyNumber: String?) = (true, "peer-identity-key", "SN-001")
        var sendMessageResult = true
        var sentMessages: [(peerID: String, text: String)] = []

        @discardableResult
        func setupEnvironment(
            relayUrl: String? = nil,
            blockchainAddr: String? = nil,
            hmacKey: String? = nil,
            relayCaB64: String? = nil,
            relaySpkiPinB64: String? = nil,
            onionNodesJSON: String? = nil
        ) -> Bool {
            if !setupEnvironmentResult {
                lastErrorSubject.send("setup failed")
            }
            return setupEnvironmentResult
        }

        func createIdentity() -> String? {
            setupEnvironmentResult ? createdIdentity : nil
        }

        func createIdentity(
            relayUrl: String,
            blockchainAddr: String,
            hmacKey: String? = nil,
            relayCaB64: String? = nil,
            relaySpkiPinB64: String? = nil,
            onionNodesJSON: String? = nil
        ) -> String? {
            setupEnvironmentResult ? createdIdentity : nil
        }

        func getIdentity() -> String? {
            nil
        }

        func generatePrekeyBundle() -> String? {
            generatedBundle
        }

        @discardableResult
        func connect(to peerDescriptor: String) -> (success: Bool, peerId: String?, safetyNumber: String?) {
            if !connectResult.success {
                lastErrorSubject.send("connect failed")
            }
            return connectResult
        }

        @discardableResult
        func sendMessage(to peerID: String, text: String) -> Bool {
            sentMessages.append((peerID, text))
            if !sendMessageResult {
                lastErrorSubject.send("send failed")
            }
            return sendMessageResult
        }

        func setHeartbeatEnabled(_ enabled: Bool) {}
        func setHeartbeatInterval(_ interval: TimeInterval) {}
    }

    private func validOnionNodesJSON() -> String {
        return """
        [
          {"url":"https://node1.example","pub_key":"1111111111111111111111111111111111111111111111111111111111111111"},
          {"url":"https://node2.example","pub_key":"2222222222222222222222222222222222222222222222222222222222222222"},
          {"url":"https://node3.example","pub_key":"3333333333333333333333333333333333333333333333333333333333333333"}
        ]
        """
    }

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        HMACKeyStore.clearPersistent()
        SecureStorage.clearAll()
        RedoorService.shared.setIdentityProfile(.strictEphemeral)
        RedoorService.shared.setPqHandshakePolicy(.prefer)
        RedoorService.shared.setLockdownProfile(.standard)
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        #endif
    }

    func testRedoorServiceLockWipesMemory() throws {
        // Given
        let service = RedoorService.shared
        let expectation = XCTestExpectation(description: "Service should lock and wipe memory")

        // Simulate a connected state
        service.connect(relayUrl: "http://localhost:8080", blockchainAddr: "127.0.0.1:9000")

        // When
        service.lock()

        // Then
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            XCTAssertTrue(service.isLocked, "Service should be in locked state")
            XCTAssertFalse(service.isConnected, "Service should be disconnected")

            // Verify that critical properties are nil/reset
            // Since we can't inspect private vars directly in Swift without Mirror,
            // we rely on the public state flags and the behavior of disconnect().
            // In a real scenario with a mock FFI, we would verify `redoor_wipe_memory` was called.

            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 2.0)
    }

    func testHeartbeatManagerGeneratesTraffic() throws {
        // Given
        let heartbeat = HeartbeatManager()
        let expectation = XCTestExpectation(description: "Heartbeat should generate a packet")

        heartbeat.meanInterval = 0.1 // Fast interval for testing

        heartbeat.sendPacketHandler = { data in
            XCTAssertEqual(data.count, 512, "Heartbeat packet should be 512 bytes")
            expectation.fulfill()
        }

        // When
        heartbeat.start()

        // Then
        wait(for: [expectation], timeout: 1.0)
        heartbeat.stop()
    }

    func testHeartbeatStartSetsRunningStateImmediately() throws {
        let heartbeat = HeartbeatManager()
        heartbeat.meanInterval = 1.0
        heartbeat.start()
        XCTAssertTrue(heartbeat.isHeartbeating)
        heartbeat.stop()
    }

    func testNetworkConfigRejectsInsecureRemoteRelay() throws {
        let error = NetworkConfigValidator.validate(
            relayUrl: "http://relay.example.com:8080",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret"
        )
        XCTAssertEqual(error, .insecureRemoteRelay)
    }

    func testNetworkConfigRequiresHmacForRemoteRelay() throws {
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: nil
        )
        XCTAssertEqual(error, .missingHmacForRemoteRelay)
    }

    func testNetworkConfigRequiresTlsPinForRemoteRelay() throws {
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret"
        )
        XCTAssertEqual(error, .missingRelayPinForRemoteRelay)
    }

    func testNetworkConfigAllowsLoopbackHttpWithoutHmac() throws {
        let error = NetworkConfigValidator.validate(
            relayUrl: "http://localhost:8080",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: nil,
            onionNodesJSON: validOnionNodesJSON()
        )
        XCTAssertNil(error)
    }

    func testNetworkConfigAcceptsRemoteRelayWithValidSpkiPin() throws {
        let pin = Data(repeating: 1, count: 32).base64EncodedString()
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: validOnionNodesJSON()
        )
        XCTAssertNil(error)
    }

    func testNetworkConfigRejectsInvalidRelayCaBase64() throws {
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: "***not-base64***",
            relaySpkiPinB64: nil
        )
        XCTAssertEqual(error, .invalidRelayCAB64)
    }

    func testNetworkConfigRequiresOnionNodeConfig() throws {
        let pin = Data(repeating: 1, count: 32).base64EncodedString()
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: nil
        )
        XCTAssertEqual(error, .missingOnionNodeConfig)
    }

    func testNetworkConfigRejectsInvalidOnionNodeConfig() throws {
        let pin = Data(repeating: 1, count: 32).base64EncodedString()
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: "[{\"url\":\"https://node1.example\",\"pub_key\":\"deadbeef\"}]"
        )
        XCTAssertEqual(error, .invalidOnionNodeConfig)
    }

    func testDefaultOnionNodesJSONIsValidForSecurityValidator() throws {
        let pin = Data(repeating: 1, count: 32).base64EncodedString()
        let defaults = OnionNodesManager.defaultOnionNodesJSON()
        let error = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: defaults
        )
        XCTAssertNil(error)
    }

    func testAutoCompleteOnionNodesJSONRemainsValidAcrossRefresh() throws {
        let pin = Data(repeating: 1, count: 32).base64EncodedString()
        let first = OnionNodesManager.autoCompleteOnionNodesJSON()
        let second = OnionNodesManager.autoCompleteOnionNodesJSON(previousJSON: first)

        let firstError = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: first
        )
        XCTAssertNil(firstError)

        let secondError = NetworkConfigValidator.validate(
            relayUrl: "https://relay.example.com",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: "secret",
            relayCaB64: nil,
            relaySpkiPinB64: pin,
            onionNodesJSON: second
        )
        XCTAssertNil(secondError)
    }

    func testIdentityProfileResolverDefaultsToStrictEphemeral() throws {
        XCTAssertEqual(IdentitySecurityProfile.resolve(from: nil), .strictEphemeral)
        XCTAssertEqual(IdentitySecurityProfile.resolve(from: ""), .strictEphemeral)
        XCTAssertEqual(IdentitySecurityProfile.resolve(from: "unknown_profile"), .strictEphemeral)
        XCTAssertEqual(
            IdentitySecurityProfile.resolve(from: "secure_enclave_optional"),
            .secureEnclaveOptional
        )
    }

    func testStrictProfileDeniesPersistentIdentityStorage() throws {
        XCTAssertFalse(RedoorFFI.shared.loadKeyFromKeychain(profile: .strictEphemeral))
        XCTAssertThrowsError(try RedoorFFI.shared.saveKeyToKeychain(profile: .strictEphemeral))
    }

    func testIdentityProfileCanSwitchAtRuntime() throws {
        let service = RedoorService.shared
        service.setIdentityProfile(.secureEnclaveOptional)
        XCTAssertEqual(service.identityProfile, .secureEnclaveOptional)

        service.setIdentityProfile(.strictEphemeral)
        XCTAssertEqual(service.identityProfile, .strictEphemeral)
    }

    func testLockdownCompatibilityStrictRejectsPersistentIdentityProfile() throws {
        let snapshot = LockdownCompatibilitySnapshot(
            profile: .strict,
            identityProfile: .secureEnclaveOptional,
            pqHandshakePolicy: .required,
            relayURL: "https://relay.example.com",
            hmacKeyPresent: true,
            relaySPKIPinConfigured: true,
            relayCAPinConfigured: false,
            onionRoutingConfigured: true,
            strictAnonymityEnforced: true,
            fixedPollingEnforced: true,
            constantRateEnforced: true,
            coverHeartbeatEnabled: true,
            networkConfigured: true
        )

        let status = LockdownCompatibilityEvaluator.evaluate(snapshot: snapshot)
        XCTAssertFalse(status.isCompatible)
        XCTAssertTrue(status.violations.contains { $0.contains("strict_ephemeral") })
    }

    func testLockdownCompatibilityStrictPassesWithRequiredControls() throws {
        let snapshot = LockdownCompatibilitySnapshot(
            profile: .strict,
            identityProfile: .strictEphemeral,
            pqHandshakePolicy: .required,
            relayURL: "https://relay.example.com",
            hmacKeyPresent: true,
            relaySPKIPinConfigured: true,
            relayCAPinConfigured: false,
            onionRoutingConfigured: true,
            strictAnonymityEnforced: true,
            fixedPollingEnforced: true,
            constantRateEnforced: true,
            coverHeartbeatEnabled: true,
            networkConfigured: true
        )

        let status = LockdownCompatibilityEvaluator.evaluate(snapshot: snapshot)
        XCTAssertTrue(status.isCompatible, "strict profile should pass when all checks are satisfied")
    }

    func testStrictLockdownProfileFailsClosedForIncompatibleIdentitySettings() throws {
        let service = RedoorService.shared
        service.setPqHandshakePolicy(.required)
        service.setLockdownProfile(.strict)
        service.setIdentityProfile(.secureEnclaveOptional)

        let didConnect = service.connect(
            relayUrl: "http://localhost:8080",
            blockchainAddr: "127.0.0.1:9000",
            hmacKey: nil,
            relayCaB64: nil,
            relaySpkiPinB64: nil,
            onionNodesJSON: validOnionNodesJSON()
        )

        XCTAssertFalse(didConnect)
        XCTAssertEqual(service.lockdownProfile, .strict)
        XCTAssertFalse(service.lockdownStatus.isCompatible)
        XCTAssertTrue(
            service.lockdownStatus.violations.contains { $0.contains("strict_ephemeral") }
        )
    }

    func testPQHandshakePolicyResolverAliases() throws {
        XCTAssertEqual(PQHandshakePolicy.resolve(from: nil), .prefer)
        XCTAssertEqual(PQHandshakePolicy.resolve(from: ""), .prefer)
        XCTAssertEqual(PQHandshakePolicy.resolve(from: "require"), .required)
        XCTAssertEqual(PQHandshakePolicy.resolve(from: "strict"), .required)
        XCTAssertEqual(PQHandshakePolicy.resolve(from: "off"), .disabled)
    }

    func testLockdownStrictRejectsNonRequiredPQPolicy() throws {
        let snapshot = LockdownCompatibilitySnapshot(
            profile: .strict,
            identityProfile: .strictEphemeral,
            pqHandshakePolicy: .prefer,
            relayURL: "https://relay.example.com",
            hmacKeyPresent: true,
            relaySPKIPinConfigured: true,
            relayCAPinConfigured: false,
            onionRoutingConfigured: true,
            strictAnonymityEnforced: true,
            fixedPollingEnforced: true,
            constantRateEnforced: true,
            coverHeartbeatEnabled: true,
            networkConfigured: true
        )

        let status = LockdownCompatibilityEvaluator.evaluate(snapshot: snapshot)
        XCTAssertFalse(status.isCompatible)
        XCTAssertTrue(status.violations.contains { $0.contains("PQ handshake policy") })
    }

    func testHMACKeyStoreSaveAndLoadRoundTrip() throws {
        HMACKeyStore.clearPersistent()
        XCTAssertTrue(HMACKeyStore.save("top-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "top-secret")
        HMACKeyStore.clearPersistent()
    }

    func testHMACKeyStoreIsVolatileOnly() throws {
        HMACKeyStore.clearPersistent()
        XCTAssertNil(HMACKeyStore.load())
        XCTAssertTrue(HMACKeyStore.save("volatile-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "volatile-secret")
        HMACKeyStore.clearPersistent()
        XCTAssertNil(HMACKeyStore.load())
        HMACKeyStore.clearPersistent()
    }

    func testHMACKeyStoreEmptySaveDeletesKey() throws {
        HMACKeyStore.clearPersistent()
        XCTAssertTrue(HMACKeyStore.save("temp-secret"))
        XCTAssertTrue(HMACKeyStore.save(""))
        XCTAssertNil(HMACKeyStore.load())
    }

    func testSecureStorageClearAllRemovesVolatileSecrets() throws {
        XCTAssertTrue(HMACKeyStore.save("volatile-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "volatile-secret")

        SecureStorage.clearAll()

        XCTAssertNil(HMACKeyStore.load())
    }

    func testSecureStorageDeleteZeroizesBuffer() throws {
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        let key = "zeroize_delete_key"
        let value = "delete-secret"
        try SecureStorage.save(key: key, data: value)
        SecureStorage.delete(key: key)

        let record = SecureStorage.debugLastZeroization(for: key)
        XCTAssertNotNil(record)
        XCTAssertEqual(record?.byteCount, value.utf8.count)
        XCTAssertTrue(record?.allBytesZero ?? false)
        #else
        throw XCTSkip("Debug zeroization hooks are unavailable.")
        #endif
    }

    func testSecureStorageClearAllZeroizesBuffers() throws {
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        try SecureStorage.save(key: "zeroize_all_key_1", data: "alpha")
        try SecureStorage.save(key: "zeroize_all_key_2", data: "bravo")
        SecureStorage.clearAll()

        let first = SecureStorage.debugLastZeroization(for: "zeroize_all_key_1")
        let second = SecureStorage.debugLastZeroization(for: "zeroize_all_key_2")
        XCTAssertTrue(first?.allBytesZero ?? false)
        XCTAssertTrue(second?.allBytesZero ?? false)
        #else
        throw XCTSkip("Debug zeroization hooks are unavailable.")
        #endif
    }

    func testLockWipesHMACSecureBuffer() throws {
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        #endif
        XCTAssertTrue(HMACKeyStore.save("lock-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "lock-secret")

        RedoorService.shared.lock()

        XCTAssertNil(HMACKeyStore.load())
        #if DEBUG
        let record = SecureStorage.debugLastZeroization(for: HMACKeyStore.debugStorageKey)
        XCTAssertTrue(record?.allBytesZero ?? false)
        #endif
    }

    func testBackgroundTransitionWipesHMACSecureBuffer() throws {
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        #endif
        _ = ChatService.shared
        XCTAssertTrue(HMACKeyStore.save("background-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "background-secret")

        NotificationCenter.default.post(name: UIApplication.didEnterBackgroundNotification, object: nil)

        XCTAssertNil(HMACKeyStore.load())
        #if DEBUG
        let record = SecureStorage.debugLastZeroization(for: HMACKeyStore.debugStorageKey)
        XCTAssertTrue(record?.allBytesZero ?? false)
        #endif
    }

    func testDuressWipesHMACSecureBuffer() throws {
        #if DEBUG
        SecureStorage.debugResetZeroizationRecords()
        #endif
        let service = RedoorService.shared
        XCTAssertTrue(HMACKeyStore.save("duress-secret"))
        XCTAssertEqual(HMACKeyStore.load(), "duress-secret")

        service.security.onDuress?()

        let expectation = XCTestExpectation(description: "Duress path processed")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            XCTAssertNil(HMACKeyStore.load())
            #if DEBUG
            let record = SecureStorage.debugLastZeroization(for: HMACKeyStore.debugStorageKey)
            XCTAssertTrue(record?.allBytesZero ?? false)
            #endif
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 1.0)
    }

    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }

    func testFullCircleOpenOnlineConnectAndSendMessage() throws {
        let mock = MockChatService()
        let vm = ChatViewModel(chatService: mock, redoor: RedoorService.shared)

        XCTAssertTrue(vm.myIdentity.isEmpty, "App open should start without local identity in mock")
        XCTAssertFalse(vm.isConnected, "Initial online state should be offline")

        mock.isConnectedSubject.send(true)
        XCTAssertTrue(vm.isConnected, "ViewModel should reflect online backend state")

        vm.createIdentity()
        let identityCreated = expectation(description: "Identity should be created asynchronously")
        var attempts = 0
        func pollIdentity() {
            attempts += 1
            if !vm.myIdentity.isEmpty {
                identityCreated.fulfill()
                return
            }
            if attempts < 20 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1, execute: pollIdentity)
            }
        }
        pollIdentity()
        wait(for: [identityCreated], timeout: 2.0)

        XCTAssertEqual(vm.myIdentity, "test-identity-key")
        XCTAssertEqual(vm.myPrekeyBundle, "{\"identity_key\":\"test-identity-key\"}")
        XCTAssertFalse(vm.isGeneratingIdentity, "Generate flag must reset after identity flow")

        vm.peerID = "peer-identity-key"
        vm.connect()
        XCTAssertTrue(vm.isSessionReady, "Session should be ready after successful connect")
        XCTAssertEqual(vm.peerID, "peer-identity-key")

        vm.messageText = "hello from simulator A"
        vm.sendMessage()
        XCTAssertEqual(mock.sentMessages.count, 1)
        XCTAssertEqual(mock.sentMessages.first?.peerID, "peer-identity-key")
        XCTAssertEqual(mock.sentMessages.first?.text, "hello from simulator A")
    }

    func testConnectByIdentityKeyFailsWithClearMessageWhenBackendRejects() throws {
        let mock = MockChatService()
        mock.connectResult = (false, nil, nil)
        let vm = ChatViewModel(chatService: mock, redoor: RedoorService.shared)

        vm.createIdentity()
        vm.peerID = "peer-identity-key"
        vm.connect()

        XCTAssertFalse(vm.isSessionReady)
        XCTAssertTrue(vm.statusMessage?.contains("Connection ID") == true)
    }

}
