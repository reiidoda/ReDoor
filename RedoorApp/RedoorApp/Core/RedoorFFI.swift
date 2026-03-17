import Foundation
import Darwin
import Security

// --- Manual C Function Declarations (Bypassing Bridging Header) ---
@_silgen_name("redoor_init_runtime")
func redoor_init_runtime() -> Int32

@_silgen_name("redoor_scripted_loopback_ext")
func redoor_scripted_loopback_ext(_ msg: UnsafePointer<CChar>?, _ relay: UnsafePointer<CChar>?, _ chain: UnsafePointer<CChar>?, _ hmac: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_set_relay_hmac_b64")
func redoor_set_relay_hmac_b64(_ key: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_set_proxy")
func redoor_set_proxy(_ url: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_init_env")
func redoor_init_env(_ relay: UnsafePointer<CChar>?, _ chain: UnsafePointer<CChar>?, _ hmac: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_create_identity")
func redoor_create_identity() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_identity_unlock")
func redoor_identity_unlock(_ plaintext_b64: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_identity_get_data_to_wrap")
func redoor_identity_get_data_to_wrap() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_get_identity")
func redoor_get_identity() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_generate_prekeys")
func redoor_generate_prekeys() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_send_message")
func redoor_send_message(_ peer_id: UnsafePointer<CChar>?, _ msg: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_poll_messages")
func redoor_poll_messages() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_mark_message_read")
func redoor_mark_message_read(_ peer_id: UnsafePointer<CChar>?, _ msg_id: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_delete_message")
func redoor_delete_message(_ peer_id: UnsafePointer<CChar>?, _ msg_id: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_free_string")
func redoor_free_string(_ s: UnsafeMutablePointer<CChar>?)

@_silgen_name("redoor_wipe_memory")
func redoor_wipe_memory()

@_silgen_name("redoor_enter_duress_mode")
func redoor_enter_duress_mode() -> Int32

@_silgen_name("redoor_flag_compromise_indicator")
func redoor_flag_compromise_indicator(_ peer_id: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_connect_via_qr")
public func redoor_connect_via_qr(_ qr_json: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_has_session")
public func redoor_has_session(_ peer: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_get_safety_number")
public func redoor_get_safety_number(_ peer: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_get_network_status")
public func redoor_get_network_status() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_enable_fixed_polling")
public func redoor_enable_fixed_polling(_ interval_ms: UInt64) -> Int32

@_silgen_name("redoor_enable_strict_anonymity")
public func redoor_enable_strict_anonymity(_ enable: Int32) -> Int32

@_silgen_name("redoor_configure_onion_routing")
public func redoor_configure_onion_routing(_ nodes_json: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_get_onion_status")
public func redoor_get_onion_status() -> UnsafeMutablePointer<CChar>?

// --- End C Declarations ---

private typealias RedoorOptionalSetStringFn = @convention(c) (UnsafePointer<CChar>?) -> Int32

private func resolveOptionalSetStringFn(symbolName: String) -> RedoorOptionalSetStringFn? {
    guard let processHandle = dlopen(nil, RTLD_NOW) else { return nil }
    guard let raw = dlsym(processHandle, symbolName) else { return nil }
    return unsafeBitCast(raw, to: RedoorOptionalSetStringFn.self)
}

private func callOptionalSetStringFn(symbolName: String, value: String?) -> Bool {
    let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    guard let fn = resolveOptionalSetStringFn(symbolName: symbolName) else {
        // Backward compatibility with older Rust staticlibs that do not export these functions.
        return trimmed.isEmpty
    }
    if trimmed.isEmpty {
        return fn(nil) == 0
    }
    return trimmed.withCString { ptr in
        fn(ptr) == 0
    }
}

public enum RedoorError: Error {
    case runtimeInitFailed
    case loopbackFailed(Int32)
    case keychain(OSStatus)
    case generic(String)
}

public struct ChatMessage: Identifiable, Decodable {
    public let id = UUID()
    public let sender: String
    public let text: String
    public let type: String? // Expected "text" in message-only mode.

    private enum CodingKeys: String, CodingKey {
        case sender, text, type
    }

    public init(sender: String, text: String, type: String = "text") {
        self.sender = sender
        self.text = text
        self.type = type
    }
}

public final class RedoorFFI {
    public static let shared = RedoorFFI()
    private init() {
        _ = redoor_init_runtime()
    }

    public func setHmac(base64: String) {
        base64.withCString { ptr in
            _ = redoor_set_relay_hmac_b64(ptr)
        }
    }

    @discardableResult
    public func setRelayCAB64(_ base64DER: String?) -> Bool {
        return callOptionalSetStringFn(symbolName: "redoor_set_relay_ca_b64", value: base64DER)
    }

    @discardableResult
    public func setRelaySPKIPinB64(_ pinB64: String?) -> Bool {
        return callOptionalSetStringFn(symbolName: "redoor_set_relay_spki_pin_b64", value: pinB64)
    }

    @discardableResult
    public func setPqHandshakePolicy(_ policy: String?) -> Bool {
        return callOptionalSetStringFn(symbolName: "redoor_set_pq_handshake_policy", value: policy)
    }

    @discardableResult
    public func configureOnionRouting(nodesJSON: String?) -> Bool {
        let trimmed = nodesJSON?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !trimmed.isEmpty else { return false }
        return trimmed.withCString { ptr in
            redoor_configure_onion_routing(ptr) == 0
        }
    }

    @discardableResult
    public func flagCompromiseIndicator(peerID: String? = nil) -> Bool {
        let trimmed = peerID?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if trimmed.isEmpty {
            return redoor_flag_compromise_indicator(nil) == 0
        }
        return trimmed.withCString { ptr in
            redoor_flag_compromise_indicator(ptr) == 0
        }
    }

    public func onionStatus() -> (enabled: Bool, nodeCount: Int)? {
        guard let ptr = redoor_get_onion_status() else { return nil }
        defer { redoor_free_string(ptr) }
        let json = String(cString: ptr)
        guard let data = json.data(using: .utf8) else { return nil }
        struct OnionStatus: Decodable {
            let enabled: Bool
            let nodeCount: Int

            private enum CodingKeys: String, CodingKey {
                case enabled
                case nodeCount = "node_count"
            }
        }
        guard let decoded = try? JSONDecoder().decode(OnionStatus.self, from: data) else {
            return nil
        }
        return (decoded.enabled, decoded.nodeCount)
    }

    public func setProxy(url: String?) {
        if let u = url {
            u.withCString { ptr in
                _ = redoor_set_proxy(ptr)
            }
        } else {
            _ = redoor_set_proxy(nil)
        }
    }

    // --- Stateful API ---

    public func initEnv(
        relayURL: String,
        blockchainAddr: String,
        hmacKey: String?,
        proxyURL: String? = nil
    ) {
        setProxy(url: proxyURL)
        relayURL.withCString { rPtr in
            blockchainAddr.withCString { bPtr in
                if let hmac = hmacKey {
                    hmac.withCString { hPtr in
                        _ = redoor_init_env(rPtr, bPtr, hPtr)
                    }
                } else {
                    _ = redoor_init_env(rPtr, bPtr, nil)
                }
            }
        }
    }

    public func createIdentity() -> String {
        guard let ptr = redoor_create_identity() else { return "" }
        let str = String(cString: ptr)
        redoor_free_string(ptr)
        return str
    }

    public func restoreIdentity(privateKeyHex: Data) -> Bool {
        var data = privateKeyHex
        data.append(0) // Null-terminate for C
        let result = data.withUnsafeBytes { rawBuffer -> Bool in
            if let baseAddr = rawBuffer.baseAddress {
                let ptr = baseAddr.assumingMemoryBound(to: CChar.self)
                return redoor_identity_unlock(ptr) == 0
            }
            return false
        }
        data.resetBytes(in: 0..<data.count)
        return result
    }

    public func getPrivateKey() -> Data? {
        guard let ptr = redoor_identity_get_data_to_wrap() else { return nil }
        let len = strlen(ptr)
        let data = Data(bytes: ptr, count: Int(len))
        // Security: Zero out the sensitive C-string buffer before freeing
        memset(ptr, 0, Int(len))
        redoor_free_string(ptr)
        return data
    }

    public func getIdentity() -> String? {
        guard let ptr = redoor_get_identity() else { return nil }
        let str = String(cString: ptr)
        redoor_free_string(ptr)
        return str
    }

    public func generatePrekeys() -> String? {
        guard let ptr = redoor_generate_prekeys() else { return nil }
        let str = String(cString: ptr)
        redoor_free_string(ptr)
        return str
    }

    public func sendMessage(peerID: String, text: String) throws {
        var rc: Int32 = 0
        peerID.withCString { pPtr in
            text.withCString { tPtr in
                rc = redoor_send_message(pPtr, tPtr)
            }
        }
        if rc != 0 {
            throw RedoorError.generic("Send failed with code \(rc)")
        }
    }

    public func pollMessages() -> [ChatMessage] {
        guard let ptr = redoor_poll_messages() else { return [] }
        let jsonStr = String(cString: ptr)
        redoor_free_string(ptr)

        guard let data = jsonStr.data(using: .utf8) else { return [] }
        do {
            return try JSONDecoder().decode([ChatMessage].self, from: data)
        } catch {
            return []
        }
    }

    @discardableResult
    public func consumeMessage(peerID: String, messageID: String) -> Bool {
        var markRc: Int32 = -1
        var deleteRc: Int32 = -1
        peerID.withCString { pPtr in
            messageID.withCString { mPtr in
                markRc = redoor_mark_message_read(pPtr, mPtr)
                deleteRc = redoor_delete_message(pPtr, mPtr)
            }
        }
        return markRc == 0 || deleteRc == 0
    }

    // Legacy loopback for testing
    public func runLoopback(message: String = "hello-ios",
                            relayURL: String,
                            blockchainAddr: String,
                            hmacBase64: String? = nil,
                            proxyURL: String? = nil) throws {
        var rc: Int32 = 0
        setProxy(url: proxyURL)
        message.withCString { msgPtr in
            relayURL.withCString { relayPtr in
                blockchainAddr.withCString { chainPtr in
                    if let hmac = hmacBase64 {
                        hmac.withCString { hmacPtr in
                            rc = redoor_scripted_loopback_ext(msgPtr, relayPtr, chainPtr, hmacPtr)
                        }
                    } else {
                        rc = redoor_scripted_loopback_ext(msgPtr, relayPtr, chainPtr, nil)
                    }
                }
            }
        }
        if rc != 0 {
            throw RedoorError.loopbackFailed(rc)
        }
    }

    // --- Keychain Helpers ---

    private func keychainBaseQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    func saveKeyToKeychain(
        profile: IdentitySecurityProfile,
        service: String = "redoor",
        account: String = "identity"
    ) throws {
        guard profile.allowsPersistentIdentityMaterial else {
            throw RedoorError.generic("Persistent key storage is disabled in strict_ephemeral mode.")
        }

        guard var wrappedIdentity = getPrivateKey(), !wrappedIdentity.isEmpty else {
            throw RedoorError.generic("No identity material available to persist.")
        }
        defer {
            wrappedIdentity.resetBytes(in: 0..<wrappedIdentity.count)
        }

        let deleteStatus = SecItemDelete(keychainBaseQuery(service: service, account: account) as CFDictionary)
        if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
            throw RedoorError.keychain(deleteStatus)
        }

        var attributes = keychainBaseQuery(service: service, account: account)
        attributes[kSecValueData as String] = wrappedIdentity
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw RedoorError.keychain(status)
        }
    }

    func loadKeyFromKeychain(
        profile: IdentitySecurityProfile,
        service: String = "redoor",
        account: String = "identity"
    ) -> Bool {
        guard profile.allowsPersistentIdentityMaterial else {
            return false
        }

        var query = keychainBaseQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, var wrappedIdentity = item as? Data, !wrappedIdentity.isEmpty else {
            return false
        }
        defer {
            wrappedIdentity.resetBytes(in: 0..<wrappedIdentity.count)
        }
        return restoreIdentity(privateKeyHex: wrappedIdentity)
    }

    func deleteKeyFromKeychain(
        profile: IdentitySecurityProfile,
        service: String = "redoor",
        account: String = "identity"
    ) {
        guard profile.allowsPersistentIdentityMaterial else {
            return
        }
        _ = SecItemDelete(keychainBaseQuery(service: service, account: account) as CFDictionary)
    }
}
