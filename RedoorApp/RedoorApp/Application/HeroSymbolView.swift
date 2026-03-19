import SwiftUI

struct HeroSymbolView: View {
    var size: CGFloat = 96
    var color: Color = .redoorText
    var accessibilityText: String = "Hero symbol"

    var body: some View {
        GeometryReader { geometry in
            let side = min(geometry.size.width, geometry.size.height)
            let center = CGPoint(x: side * 0.5, y: side * 0.5)

            let outerRing = side * 0.4583
            let middleRing = side * 0.3917
            let innerRing = side * 0.3000
            let hexRing = side * 0.2833

            let vertices = hexagonPoints(center: center, radius: hexRing)
            let top = vertices[0]
            let upperRight = vertices[1]
            let lowerRight = vertices[2]
            let bottom = vertices[3]
            let lowerLeft = vertices[4]
            let upperLeft = vertices[5]

            ZStack {
                Circle()
                    .stroke(color.opacity(0.28), lineWidth: max(1.2, side * 0.016))
                    .frame(width: outerRing * 2, height: outerRing * 2)

                Circle()
                    .stroke(color.opacity(0.58), lineWidth: max(1.1, side * 0.014))
                    .frame(width: middleRing * 2, height: middleRing * 2)

                Circle()
                    .stroke(color.opacity(0.9), lineWidth: max(1.0, side * 0.011))
                    .frame(width: innerRing * 2, height: innerRing * 2)

                Path { path in
                    path.addLines(vertices + [top])
                }
                .stroke(
                    color.opacity(0.92),
                    style: StrokeStyle(
                        lineWidth: max(1.1, side * 0.0092),
                        lineCap: .round,
                        lineJoin: .round
                    )
                )

                Path { path in
                    path.move(to: top)
                    path.addLine(to: bottom)
                    path.move(to: upperLeft)
                    path.addLine(to: lowerRight)
                    path.move(to: lowerLeft)
                    path.addLine(to: upperRight)
                }
                .stroke(
                    color.opacity(0.88),
                    style: StrokeStyle(
                        lineWidth: max(1.0, side * 0.0083),
                        lineCap: .round,
                        lineJoin: .round
                    )
                )

                Group {
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(top)
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(upperRight)
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(lowerRight)
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(bottom)
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(lowerLeft)
                    Circle().frame(width: side * 0.03, height: side * 0.03).position(upperLeft)
                    Circle().frame(width: side * 0.035, height: side * 0.035).position(center)
                }
                .foregroundStyle(color)
            }
            .frame(width: side, height: side)
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText)
    }

    private func hexagonPoints(center: CGPoint, radius: CGFloat) -> [CGPoint] {
        (0..<6).map { index in
            let angle = (-90.0 + Double(index) * 60.0) * .pi / 180.0
            return CGPoint(
                x: center.x + CGFloat(cos(angle)) * radius,
                y: center.y + CGFloat(sin(angle)) * radius
            )
        }
    }
}
