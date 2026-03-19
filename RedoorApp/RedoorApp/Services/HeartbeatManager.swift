import Foundation
import Combine

/// Manages the generation of constant-rate heartbeat/cover traffic packets.
/// This helps mask the timing of actual messages and maintains a steady stream of traffic.
class HeartbeatManager {
    
    /// The interval between heartbeat packets in seconds.
    /// Defaults to 1.0 second.
    var meanInterval: TimeInterval = 1.0
    
    /// Closure to be executed when a heartbeat packet is generated.
    /// The closure receives the generated data packet (typically 512 bytes).
    var sendPacketHandler: ((Data) -> Void)?
    
    private var timer: Timer?
    @Published var isHeartbeating: Bool = false
    
    deinit {
        stop()
    }
    
    /// Starts the heartbeat generator.
    func start() {
        // Invalidate any existing timer to avoid duplicates
        stop()
        isHeartbeating = true
        
        timer = Timer.scheduledTimer(withTimeInterval: meanInterval, repeats: true) { [weak self] _ in
            self?.triggerHeartbeat()
        }
    }
    
    /// Stops the heartbeat generator.
    func stop() {
        timer?.invalidate()
        timer = nil
        isHeartbeating = false
    }
    
    private func triggerHeartbeat() {
        // Generate cover traffic of the standard bucket size (512 bytes)
        let packet = SecurityUtils.generateCoverTraffic(size: 512)
        sendPacketHandler?(packet)
    }
}
