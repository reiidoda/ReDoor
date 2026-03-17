import SwiftUI

struct ChatView: View {
    @ObservedObject var viewModel: ChatViewModel
    @State private var isShowingSettings = false

    var body: some View {
        ZStack {
            FuturisticBackground()

            VStack(spacing: 12) {
                headerPanel

                if let safety = viewModel.safetyNumber {
                    infoPanel(text: "Safety: \(safety)", singleLine: true)
                }

                if let status = viewModel.statusMessage, !status.isEmpty {
                    infoPanel(text: status)
                }

                messagesPanel
                composerPanel
            }
            .padding(.horizontal, 16)
            .padding(.top, 10)
            .padding(.bottom, 8)
        }
        .navigationTitle("Redoor")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $isShowingSettings) {
            SettingsView()
        }
        .onAppear {
            if !ProcessInfo.processInfo.isRunningUnitTests && viewModel.myIdentity.isEmpty {
                viewModel.createIdentity()
            }
        }
    }

    private var headerPanel: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(viewModel.isConnected ? Color.green : Color.red)
                .frame(width: 10, height: 10)
                .shadow(color: viewModel.isConnected ? Color.green.opacity(0.65) : Color.red.opacity(0.65), radius: 4)

            Text(viewModel.isConnected ? "Connected" : "Disconnected")
                .font(.headline)
                .foregroundColor(.redoorText)

            if viewModel.isSessionReady {
                Text("Session Ready")
                    .font(.caption2)
                    .foregroundColor(.redoorText)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(Color.white.opacity(0.12))
                    )
                    .overlay(
                        Capsule()
                            .stroke(Color.white.opacity(0.28), lineWidth: 1)
                    )
            }

            Spacer()

            iconButton(systemName: "arrow.clockwise", action: {
                viewModel.connect()
            })

            iconButton(systemName: "gearshape.fill", action: {
                isShowingSettings = true
            })
        }
        .padding(12)
        .monochromePanel()
    }

    private var messagesPanel: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(viewModel.messages) { message in
                        MessageBubble(message: message)
                            .id(message.id)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 10)
                .animation(.easeInOut(duration: 0.2), value: viewModel.messages)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .monochromePanel()
            .onChange(of: viewModel.messages) { _, _ in
                withAnimation {
                    proxy.scrollTo(viewModel.messages.last?.id, anchor: .bottom)
                }
            }
        }
    }

    private var composerPanel: some View {
        VStack(spacing: 10) {
            TextField("Peer ID", text: $viewModel.peerID)
                .textFieldStyle(GlassTextFieldStyle())

            HStack(spacing: 10) {
                TextField("Enter message", text: $viewModel.messageText)
                    .textFieldStyle(GlassTextFieldStyle())

                Button(action: {
                    viewModel.sendMessage()
                }) {
                    Image(systemName: "paperplane.fill")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(canSendMessage ? .redoorText : .redoorMuted)
                        .frame(width: 42, height: 42)
                        .background(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .fill(canSendMessage ? Color.white.opacity(0.16) : Color.redoorSurfaceStrong.opacity(0.75))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(canSendMessage ? Color.white.opacity(0.36) : Color.redoorBorder, lineWidth: 1)
                        )
                }
                .disabled(!canSendMessage)
            }
        }
        .padding(12)
        .monochromePanel()
    }

    private var canSendMessage: Bool {
        viewModel.isSessionReady && !viewModel.peerID.isEmpty
    }

    private func infoPanel(text: String, singleLine: Bool = false) -> some View {
        Text(text)
            .font(.footnote)
            .foregroundColor(.redoorTextSoft)
            .lineLimit(singleLine ? 1 : nil)
            .truncationMode(singleLine ? .middle : .tail)
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .monochromePanel(cornerRadius: 14)
    }

    private func iconButton(systemName: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: systemName)
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(.redoorText)
                .frame(width: 34, height: 34)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.white.opacity(0.1))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .stroke(Color.redoorBorder, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }
}

private extension ProcessInfo {
    var isRunningUnitTests: Bool {
        environment["XCTestConfigurationFilePath"] != nil
    }
}
