import SwiftUI

struct SettingsView: View {
    @ObservedObject var redoor = RedoorService.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            ZStack {
                FuturisticBackground()

                ScrollView(showsIndicators: false) {
                    VStack(spacing: 16) {
                        identitySection
                        securityActiveSection
                        emergencySection
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                    .padding(.bottom, 28)
                    .accessibilityIdentifier("settings_screen")
                }
            }
            .navigationTitle("Security Status")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                    .foregroundColor(.redoorText)
                    .accessibilityIdentifier("settings_done_button")
                }
            }
        }
        .preferredColorScheme(.dark)
    }

    private var identitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("YOUR IDENTITY")

            if let identity = redoor.identity.current() {
                Text(identity)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.redoorTextSoft)
                    .textSelection(.enabled)
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

                Button(action: {
                    UIPasteboard.general.string = identity
                }) {
                    Label("Copy Identity", systemImage: "doc.on.doc")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.redoorText)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .fill(Color.white.opacity(0.12))
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(Color.white.opacity(0.28), lineWidth: 1)
                        )
                }
            } else {
                Text("No Identity Created")
                    .font(.subheadline)
                    .foregroundColor(.redoorMuted)
            }
        }
        .padding(14)
        .monochromePanel()
    }

    private var securityActiveSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionTitle("SECURITY FEATURES")

            Text("All security features are mandatory and always active. No user configuration allowed.")
                .font(.caption2)
                .foregroundColor(.redoorMuted)
                .padding(.bottom, 4)

            securityFeatureRow(
                icon: "checkmark.shield.fill",
                title: "End-to-End Encryption",
                status: "Double Ratchet + Post-Quantum",
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "network",
                title: "Onion Routing",
                status: "8 Mix Nodes (Geographically Diverse)",
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "waveform.circle.fill",
                title: "Cover Traffic",
                status: "Constant-Rate Masking (1s intervals)",
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "lock.shield.fill",
                title: "Perfect Secrecy",
                status: "Forward & Post-Compromise Secure",
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "key.viewfinder",
                title: "TLS Pinning",
                status: "Certificate Pinning Active",
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "lock.open.fill",
                title: "Identity Profile",
                status: redoor.identityProfile.displayName,
                isActive: true
            )

            Divider()
                .overlay(Color.white.opacity(0.1))

            securityFeatureRow(
                icon: "iphone.lockopen",
                title: "Lockdown Compatibility",
                status: redoor.lockdownProfile.displayName,
                isActive: redoor.lockdownStatus.isCompatible
            )
        }
        .padding(14)
        .monochromePanel()
    }

    private func securityFeatureRow(
        icon: String,
        title: String,
        status: String,
        isActive: Bool
    ) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .semibold))
                .foregroundColor(isActive ? .green.opacity(0.8) : .red.opacity(0.8))
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.redoorText)

                Text(status)
                    .font(.caption2)
                    .foregroundColor(.redoorMuted)
            }

            Spacer()

            Text(isActive ? "ACTIVE" : "INACTIVE")
                .font(.caption.weight(.bold))
                .foregroundColor(isActive ? .green : .red)
        }
        .padding(.vertical, 4)
    }

    private var emergencySection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionTitle("EMERGENCY")

            destructiveButton(
                title: "Activate Duress Mode",
                icon: "exclamationmark.shield.fill",
                identifier: "settings_duress_button"
            ) {
                redoor.security.enterDuressMode()
            }

            destructiveButton(
                title: "Wipe & Lock All Data",
                icon: "lock.slash.fill",
                identifier: "settings_wipe_button"
            ) {
                redoor.lock(clearPersistentIdentity: true)
            }

            Text("⚠️ These actions cannot be undone. Your identity and all messages will be permanently deleted.")
                .font(.caption2)
                .foregroundColor(.red.opacity(0.8))
        }
        .padding(14)
        .monochromePanel()
    }

    private func sectionTitle(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .fontWeight(.semibold)
            .tracking(1)
            .foregroundColor(.redoorTextSoft)
    }

    private func destructiveButton(
        title: String,
        icon: String,
        identifier: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Label(title, systemImage: icon)
                .font(.subheadline.weight(.semibold))
                .foregroundColor(.red)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 10)
                .background(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(Color.red.opacity(0.12))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(Color.red.opacity(0.3), lineWidth: 1)
                )
        }
        .accessibilityIdentifier(identifier)
    }
}
