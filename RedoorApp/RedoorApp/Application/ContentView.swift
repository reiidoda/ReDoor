import SwiftUI

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var viewModel = ChatViewModel()
    @ObservedObject private var redoor = RedoorService.shared

    var body: some View {
        ZStack {
            NavigationStack {
                SetupView(viewModel: viewModel)
                    .toolbar(.hidden, for: .navigationBar)
            }
            .preferredColorScheme(.dark)

            if redoor.isLocked {
                lockOverlay
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            guard newPhase == .active, redoor.isLocked, !redoor.isDuressMode else { return }
            redoor.unlock()
            if viewModel.myIdentity.isEmpty {
                viewModel.createIdentity()
            }
        }
    }

    private var lockOverlay: some View {
        ZStack {
            FuturisticBackground()
            VStack(spacing: 16) {
                HeroSymbolView(size: 72, accessibilityText: "Redoor hero symbol")
                Text("Redoor is locked")
                    .foregroundColor(.white)
                    .font(.headline)
                Text("Session data was wiped. Start as a new ephemeral user.")
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.85))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                Button("Start New Session") {
                    redoor.unlock()
                    if viewModel.myIdentity.isEmpty {
                        viewModel.createIdentity()
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
                .glassEffect()
            }
        }
    }
}
