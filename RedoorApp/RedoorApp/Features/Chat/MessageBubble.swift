import SwiftUI

struct MessageBubble: View {
    let message: RedoorIncomingMessage

    private var isLocalSender: Bool {
        message.sender == "me"
    }

    var body: some View {
        HStack {
            if isLocalSender {
                Spacer(minLength: 44)
            }

            Text(message.content)
                .font(.body)
                .foregroundColor(isLocalSender ? .redoorText : .redoorTextSoft)
                .padding(.horizontal, 13)
                .padding(.vertical, 11)
                .frame(maxWidth: 300, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(isLocalSender ? Color.white.opacity(0.16) : Color.redoorSurfaceStrong.opacity(0.94))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .stroke(isLocalSender ? Color.white.opacity(0.42) : Color.redoorBorderStrong, lineWidth: 1)
                )
                .shadow(color: .black.opacity(isLocalSender ? 0.32 : 0.2), radius: isLocalSender ? 7 : 4, x: 0, y: 2)

            if !isLocalSender {
                Spacer(minLength: 44)
            }
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 4)
        .transition(.asymmetric(insertion: .opacity.combined(with: .offset(y: 8)), removal: .opacity))
    }
}
