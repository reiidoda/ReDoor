import Foundation
import Security
import CommonCrypto

// MARK: - Secure Storage (Keychain)

public enum SecureStorage {
    private static let service = "redoor.secure.chat"

    public static func save(key: String, data: String) throws {
        guard let dataBytes = data.data(using: .utf8) else { return }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service
        ]
        SecItemDelete(query as CFDictionary) // Delete existing

        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
            kSecValueData as String: dataBytes,
            // kSecAttrAccessibleWhenUnlockedThisDeviceOnly ensures data is encrypted 
            // and only available when the device is unlocked. It does not migrate to new devices via backup.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw RedoorError.keychain(status) }
    }

    public static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    public static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: service
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - C Function Declarations

@_silgen_name("redoor_init_runtime")
func redoor_init_runtime() -> Int32

@_silgen_name("redoor_scripted_loopback_ext")
func redoor_scripted_loopback_ext(_ msg: UnsafePointer<CChar>?, _ relay: UnsafePointer<CChar>?, _ chain: UnsafePointer<CChar>?, _ hmac: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_set_relay_hmac_b64")
func redoor_set_relay_hmac_b64(_ key: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_set_relay_ca_b64")
func redoor_set_relay_ca_b64(_ ca: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_set_proxy")
func redoor_set_proxy(_ url: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_init_env")
func redoor_init_env(_ relay: UnsafePointer<CChar>?, _ chain: UnsafePointer<CChar>?, _ hmac: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_create_identity")
func redoor_create_identity() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_restore_identity")
func redoor_restore_identity(_ priv_key: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_get_private_key")
func redoor_get_private_key() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_get_identity")
func redoor_get_identity() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_connect_peer")
func redoor_connect_peer(_ peer_id: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_send_message")
func redoor_send_message(_ peer_id: UnsafePointer<CChar>?, _ msg: UnsafePointer<CChar>?) -> Int32

@_silgen_name("redoor_poll_messages")
func redoor_poll_messages() -> UnsafeMutablePointer<CChar>?

@_silgen_name("redoor_free_string")
func redoor_free_string(_ s: UnsafeMutablePointer<CChar>?)

// MARK: - Types

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
    // Removed type field as we only support text now
    
    private enum CodingKeys: String, CodingKey {
        case sender, text
    }
    
    public init(sender: String, text: String) {
        self.sender = sender
        self.text = text
    }
}

// MARK: - FFI Wrapper

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

    public func setRelayCA(base64: String?) {
        if let ca = base64 {
            ca.withCString { ptr in
                _ = redoor_set_relay_ca_b64(ptr)
            }
        } else {
            _ = redoor_set_relay_ca_b64(nil)
        }
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

    public func initEnv(relayURL: String, blockchainAddr: String, hmacKey: String?) {
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
    
    public func restoreIdentity(privateKeyHex: String) -> Bool {
        return privateKeyHex.withCString { ptr in
            return redoor_restore_identity(ptr) == 0
        }
    }
    
    public func getPrivateKey() -> String? {
        guard let ptr = redoor_get_private_key() else { return nil }
        let str = String(cString: ptr)
        redoor_free_string(ptr)
        return str
    }

    public func getIdentity() -> String? {
        guard let ptr = redoor_get_identity() else { return nil }
        let str = String(cString: ptr)
        redoor_free_string(ptr)
        return str
    }

    public func connectPeer(peerID: String) {
        peerID.withCString { ptr in
            _ = redoor_connect_peer(ptr)
        }
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
    
    // Legacy loopback for testing
    @discardableResult
    public func runLoopback(message: String = "hello-ios",
                            relayURL: String = "https://localhost:8443",
                            blockchainAddr: String = "http://127.0.0.1:9444",
                            hmacBase64: String? = nil) throws {
        var rc: Int32 = 0
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
}
