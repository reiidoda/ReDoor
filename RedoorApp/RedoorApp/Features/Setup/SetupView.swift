import SwiftUI

struct SetupView: View {
    @ObservedObject var viewModel: ChatViewModel
    @State private var navigateToChat = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            FuturisticBackground()

            ScrollView(showsIndicators: false) {
                VStack(spacing: 28) {
                    Spacer().frame(height: 28)
                    brandingHeader

                    if viewModel.myIdentity.isEmpty {
                        onboardingView
                    } else {
                        sessionReadyView
                    }

                    Spacer().frame(height: 12)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 30)
            }
        }
        .navigationDestination(isPresented: $navigateToChat) {
            ChatView(viewModel: viewModel)
        }
        .onReceive(viewModel.$isSessionReady) { isReady in
            if isReady {
                navigateToChat = true
            }
        }
    }

    private var brandingHeader: some View {
        VStack(spacing: 14) {
            HeroSymbolView(size: 92, accessibilityText: "Redoor hero symbol")
                .shadow(color: .redoorGlow, radius: 10, x: 0, y: 5)
                .accessibilityIdentifier("setup_hero_symbol")

            Text("ReDoor")
                .font(.system(size: 40, weight: .bold, design: .rounded))
                .foregroundColor(.redoorText)

            Text("Decentralized & Serverless")
                .font(.subheadline)
                .foregroundColor(.redoorTextSoft)
        }
        .frame(maxWidth: .infinity)
        .padding(.top, 10)
    }

    private var onboardingView: some View {
        VStack(spacing: 18) {
            Text("Your device is your server. No account. No tracking.")
                .multilineTextAlignment(.center)
                .font(.body)
                .foregroundColor(.redoorTextSoft)
                .padding(.horizontal, 8)

            Text("Military-grade end-to-end encryption with decentralized routing is always enabled.")
                .multilineTextAlignment(.center)
                .font(.caption)
                .foregroundColor(.redoorMuted)
                .padding(.horizontal, 8)

            VStack(alignment: .leading, spacing: 14) {
                sectionTitle("SECURITY ENABLED")

                VStack(alignment: .leading, spacing: 10) {
                    securityFeature("shield.fill", "End-to-End Encryption", "Double Ratchet with hybrid PQ")
                    securityFeature("network", "Onion Routing", "8 geographically-diverse mix nodes")
                    securityFeature("checkmark.shield.fill", "Cover Traffic", "Constant-rate traffic masking enabled")
                    securityFeature("lock.shield.fill", "Perfect Secrecy", "Forward & post-compromise secrecy")
                }
                .padding(12)
                .background(Color.white.opacity(0.05))
                .cornerRadius(12)
            }
            .padding(16)
            .monochromePanel()

            Button(action: {
                viewModel.createIdentity()
            }) {
                HStack(spacing: 10) {
                    if viewModel.isGeneratingIdentity {
                        ProgressView()
                            .progressViewStyle(.circular)
                            .tint(.redoorText)
                    } else {
                        Image(systemName: "person.badge.key.fill")
                    }
                    Text(viewModel.isGeneratingIdentity ? "Generating..." : "Generate Your Identity")
                }
                .fontWeight(.semibold)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color.white.opacity(0.14))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(Color.white.opacity(0.35), lineWidth: 1)
                )
                .foregroundColor(.redoorText)
            }
            .buttonStyle(.plain)
            .contentShape(Rectangle())
            .allowsHitTesting(true)
            .accessibilityIdentifier("setup_create_identity_button")

            if let status = viewModel.statusMessage, !status.isEmpty {
                Text(status)
                    .font(.footnote)
                    .foregroundColor(status.lowercased().contains("error") || status.lowercased().contains("failed") ? .red.opacity(0.8) : .redoorTextSoft)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity)
                    .monochromePanel(cornerRadius: 14)
                    .accessibilityIdentifier("setup_status_message")
            }
        }
    }

    private func securityFeature(_ icon: String, _ title: String, _ description: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(.green.opacity(0.8))
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundColor(.redoorText)

                Text(description)
                    .font(.caption2)
                    .foregroundColor(.redoorMuted)
            }

            Spacer()
        }
    }

    private var sessionReadyView: some View {
        VStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("YOUR IDENTITY")

                HStack(spacing: 12) {
                    Text(viewModel.myIdentity)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .foregroundColor(.redoorText)

                    Spacer()

                    Button(action: {
                        UIPasteboard.general.string = viewModel.myIdentity
                    }) {
                        Image(systemName: "doc.on.doc")
                            .foregroundColor(.redoorText)
                    }
                }
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Color.redoorSurfaceStrong.opacity(0.9))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(Color.redoorBorderStrong, lineWidth: 1)
                )
            }
            .padding(16)
            .monochromePanel()

            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("SHARE THIS CONNECTION ID")

                Text(viewModel.myPrekeyBundle.isEmpty ? "Connection ID will be generated automatically." : viewModel.myPrekeyBundle)
                    .font(.system(.caption2, design: .monospaced))
                    .lineLimit(4)
                    .truncationMode(.middle)
                    .foregroundColor(.redoorTextSoft)
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Color.redoorSurfaceStrong.opacity(0.9))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(Color.redoorBorderStrong, lineWidth: 1)
                    )

                HStack(spacing: 10) {
                    Button(action: {
                        viewModel.refreshPrekeyBundle()
                    }) {
                        Label("Refresh ID", systemImage: "arrow.clockwise")
                            .font(.caption.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .foregroundColor(.redoorText)
                            .background(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(Color.white.opacity(0.1))
                            )
                    }

                    Button(action: {
                        if viewModel.myPrekeyBundle.isEmpty {
                            viewModel.refreshPrekeyBundle()
                        }
                        UIPasteboard.general.string = viewModel.myPrekeyBundle
                    }) {
                        Label("Copy ID", systemImage: "doc.on.doc")
                            .font(.caption.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .foregroundColor(.redoorText)
                            .background(
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(Color.white.opacity(0.14))
                            )
                    }
                }
            }
            .padding(16)
            .monochromePanel()

            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("CONNECT TO PEER")

                TextField("Paste peer Connection ID", text: $viewModel.peerID)
                    .textFieldStyle(GlassTextFieldStyle())

                Text("For first-time chat, use the full Connection ID from the peer's Share section.")
                    .font(.caption2)
                    .foregroundColor(.redoorMuted)

                Button(action: viewModel.connect) {
                    Text("Start Secure Chat")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 13)
                        .background(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .fill(viewModel.peerID.isEmpty ? Color.redoorSurfaceStrong.opacity(0.75) : Color.white.opacity(0.16))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .stroke(viewModel.peerID.isEmpty ? Color.redoorBorder : Color.white.opacity(0.4), lineWidth: 1)
                        )
                        .foregroundColor(viewModel.peerID.isEmpty ? .redoorMuted : .redoorText)
                }
                .disabled(viewModel.peerID.isEmpty)
                .accessibilityIdentifier("setup_start_secure_chat_button")
            }
            .padding(16)
            .monochromePanel()

            if let status = viewModel.statusMessage, !status.isEmpty {
                Text(status)
                    .font(.footnote)
                    .foregroundColor(.redoorTextSoft)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 12)
                    .frame(maxWidth: .infinity)
                    .monochromePanel(cornerRadius: 14)
                    .accessibilityIdentifier("setup_status_message")
            }
        }
    }

    private func sectionTitle(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .fontWeight(.semibold)
            .tracking(1)
            .foregroundColor(.redoorTextSoft)
    }

    private func fieldLabel(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundColor(.redoorTextSoft)
    }
}
