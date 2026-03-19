import SwiftUI

enum RedoorTheme {
    enum Palette {
        static let background = Color(hex: 0x030303)
        static let backgroundAlt = Color(hex: 0x080808)
        static let surface = Color(hex: 0x0F0F0F)
        static let surfaceStrong = Color(hex: 0x171717)
        static let text = Color.white
        static let textSoft = Color(hex: 0xEFEFEF)
        static let muted = Color(hex: 0xC4C4C4)
        static let border = Color.white.opacity(0.16)
        static let borderStrong = Color.white.opacity(0.3)
        static let glow = Color.white.opacity(0.12)
    }

    enum Radius {
        static let card: CGFloat = 20
        static let field: CGFloat = 12
    }
}

private extension Color {
    init(hex: UInt32) {
        let red = Double((hex >> 16) & 0xFF) / 255.0
        let green = Double((hex >> 8) & 0xFF) / 255.0
        let blue = Double(hex & 0xFF) / 255.0
        self.init(.sRGB, red: red, green: green, blue: blue, opacity: 1.0)
    }
}

extension Color {
    static let redoorBackground = RedoorTheme.Palette.background
    static let redoorBackgroundAlt = RedoorTheme.Palette.backgroundAlt
    static let redoorSurface = RedoorTheme.Palette.surface
    static let redoorSurfaceStrong = RedoorTheme.Palette.surfaceStrong
    static let redoorText = RedoorTheme.Palette.text
    static let redoorTextSoft = RedoorTheme.Palette.textSoft
    static let redoorMuted = RedoorTheme.Palette.muted
    static let redoorBorder = RedoorTheme.Palette.border
    static let redoorBorderStrong = RedoorTheme.Palette.borderStrong
    static let redoorGlow = RedoorTheme.Palette.glow
}

struct FuturisticBackground: View {
    @State private var animate = false
    
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [.redoorBackground, .redoorBackgroundAlt],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            Circle()
                .fill(Color.redoorGlow)
                .frame(width: 340, height: 340)
                .blur(radius: 110)
                .offset(x: animate ? -100 : -50, y: animate ? -200 : -150)

            Circle()
                .fill(Color.redoorGlow.opacity(0.75))
                .frame(width: 320, height: 320)
                .blur(radius: 100)
                .offset(x: animate ? 100 : 50, y: animate ? 200 : 150)

            LinearGradient(
                colors: [.clear, Color.black.opacity(0.35)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 10).repeatForever(autoreverses: true)) {
                animate.toggle()
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

private struct MonochromePanelModifier: ViewModifier {
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        content
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(Color.redoorSurface.opacity(0.84))
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .stroke(Color.redoorBorder, lineWidth: 1)
            )
    }
}

extension View {
    func monochromePanel(cornerRadius: CGFloat = RedoorTheme.Radius.card) -> some View {
        modifier(MonochromePanelModifier(cornerRadius: cornerRadius))
    }

    // Kept for backward compatibility while migrating screens.
    func glassEffect() -> some View {
        monochromePanel(cornerRadius: RedoorTheme.Radius.card)
    }
}

struct GlassTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .padding(12)
            .foregroundColor(.redoorText)
            .background(
                RoundedRectangle(cornerRadius: RedoorTheme.Radius.field, style: .continuous)
                    .fill(Color.redoorSurfaceStrong.opacity(0.92))
            )
            .overlay(
                RoundedRectangle(cornerRadius: RedoorTheme.Radius.field, style: .continuous)
                    .stroke(Color.redoorBorderStrong, lineWidth: 1)
            )
    }
}
