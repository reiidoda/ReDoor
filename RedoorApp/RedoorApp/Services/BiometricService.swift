import LocalAuthentication
import Combine

class BiometricService {
    static let shared = BiometricService()
    
    func authenticate(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        var error: NSError?
        let reason = "Authenticate to unlock Redoor"
        
        // Check if biometric authentication is available
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, authenticationError in
                DispatchQueue.main.async {
                    completion(success)
                    if !success {
                        print("Biometric authentication failed: \(String(describing: authenticationError))")
                        RedoorService.shared.security.wipeMemory()
                    }
                }
            }
            return
        }

        // Strict fallback: require device owner authentication (passcode/biometric),
        // never auto-allow unlocks in simulator or unsupported states.
        print("Biometrics not available: \(String(describing: error))")
        error = nil
        if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authenticationError in
                DispatchQueue.main.async {
                    completion(success)
                    if !success {
                        print("Device owner authentication failed: \(String(describing: authenticationError))")
                        RedoorService.shared.security.wipeMemory()
                    }
                }
            }
            return
        }

        print("Device owner authentication unavailable: \(String(describing: error))")
        DispatchQueue.main.async {
            completion(false)
            RedoorService.shared.security.wipeMemory()
        }
    }
}
