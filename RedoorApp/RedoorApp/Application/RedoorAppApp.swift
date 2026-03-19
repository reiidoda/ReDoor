import SwiftUI

@main
struct RedoorAppApp: App {
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .onChange(of: scenePhase) { _, newPhase in
                    if newPhase == .inactive || newPhase == .background {
                        RedoorService.shared.lock()
                    }
                }
        }
    }
}
