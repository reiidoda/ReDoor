import Foundation
import Security

/// Utilities for security-critical operations such as generating cover traffic
/// and handling duress (panic) modes.
class SecurityUtils {
    
    /// Generates a block of cryptographically secure random data.
    ///
    /// - Parameter size: The number of bytes to generate.
    /// - Returns: A Data object containing random bytes.
    static func generateCoverTraffic(size: Int) -> Data {
        var data = Data(count: size)
        let result = data.withUnsafeMutableBytes { mutableBytes in
            // Ensure we have a valid base address
            guard let baseAddress = mutableBytes.baseAddress else { return Int32(-1) }
            return SecRandomCopyBytes(kSecRandomDefault, size, baseAddress)
        }
        
        if result == errSecSuccess {
            return data
        } else {
            // Fallback to Swift's random number generator if SecRandomCopyBytes fails
            return Data((0..<size).map { _ in UInt8.random(in: 0...255) })
        }
    }
    
    /// RAM-only duress helper: drop volatile in-process storage references.
    static func triggerDuressWipe() {
        SecureStorage.clearAll()
    }
}
