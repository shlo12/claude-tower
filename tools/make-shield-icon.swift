import AppKit

// Claude Shield 的应用图标：程序生成，仓库里不放设计素材。
// 深色圆角底 + 金色五边形盾 + 盾内一座三层小塔——和 Claude Tower 是同一个记号体系。
//
//   swiftc -O tools/make-shield-icon.swift -o build/make-shield-icon
//   build/make-shield-icon build/Shield.iconset

let args = CommandLine.arguments
let outDir = args.count > 1 ? args[1] : "./Shield.iconset"

let bgTop = NSColor(calibratedRed: 0.094, green: 0.110, blue: 0.157, alpha: 1)   // #181c28
let bgBot = NSColor(calibratedRed: 0.039, green: 0.047, blue: 0.071, alpha: 1)   // #0a0c12
let gold = NSColor(calibratedRed: 0.878, green: 0.706, blue: 0.361, alpha: 1)    // #e0b45c
let goldHi = NSColor(calibratedRed: 0.961, green: 0.820, blue: 0.537, alpha: 1)  // #f5d189

func makeIcon(pixels: Int) -> NSImage {
    let s = CGFloat(pixels)
    let img = NSImage(size: NSSize(width: s, height: s))
    img.lockFocus()
    guard let ctx = NSGraphicsContext.current else { img.unlockFocus(); return img }
    ctx.imageInterpolation = .high

    // 圆角底
    let inset = s * 0.085
    let rect = NSRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2)
    let radius = s * 0.225
    let bg = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)

    NSGraphicsContext.saveGraphicsState()
    bg.addClip()
    NSGradient(starting: bgTop, ending: bgBot)?.draw(in: rect, angle: -90)
    // 顶部一点金色微光，和塔的界面同一个调子
    NSGradient(colors: [gold.withAlphaComponent(0.16), gold.withAlphaComponent(0)])?
        .draw(in: NSRect(x: rect.minX, y: rect.midY, width: rect.width, height: rect.height * 0.55), angle: -90)
    NSGraphicsContext.restoreGraphicsState()

    // 细内描边：深色图标在深色 Dock 上需要一条边界
    let edge = NSBezierPath(roundedRect: rect.insetBy(dx: 0.5, dy: 0.5),
                            xRadius: radius * 0.97, yRadius: radius * 0.97)
    edge.lineWidth = max(1, s * 0.003)
    NSColor(calibratedWhite: 1, alpha: 0.10).setStroke()
    edge.stroke()

    // 盾牌：五边形，直角接头。应用图标保留硬边，菜单栏小图另用圆角轮廓，
    // 同一个金色记号，不必强行同形。
    func pt(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
        NSPoint(x: rect.minX + rect.width * x, y: rect.minY + rect.height * y)
    }
    let shield = NSBezierPath()
    shield.move(to: pt(0.20, 0.845))
    shield.line(to: pt(0.80, 0.845))
    shield.line(to: pt(0.80, 0.485))
    shield.line(to: pt(0.50, 0.155))
    shield.line(to: pt(0.20, 0.485))
    shield.close()
    shield.lineJoinStyle = .miter

    // 填充用金色渐变，描边用亮金——单色填充在深底上会显得扁
    NSGraphicsContext.saveGraphicsState()
    shield.addClip()
    NSGradient(colors: [goldHi, gold])?.draw(in: rect, angle: -90)
    NSGraphicsContext.restoreGraphicsState()

    goldHi.setStroke()
    shield.lineWidth = max(1, s * 0.028)
    shield.stroke()

    // 盾内的小塔：三层，越往上越窄
    let dark = bgBot
    dark.setFill()
    let blocks: [(CGFloat, CGFloat, CGFloat, CGFloat)] = [
        (0.375, 0.545, 0.250, 0.075),   // 基座 x, y, w, h
        (0.405, 0.620, 0.190, 0.070),
        (0.440, 0.690, 0.120, 0.065),
    ]
    for b in blocks {
        let r = NSRect(x: rect.minX + rect.width * b.0,
                       y: rect.minY + rect.height * b.1,
                       width: rect.width * b.2,
                       height: rect.height * b.3)
        NSBezierPath(rect: r).fill()
    }

    img.unlockFocus()
    return img
}

func writePNG(_ img: NSImage, pixels: Int, to path: String) {
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                     isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0) else { return }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    img.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
    NSGraphicsContext.restoreGraphicsState()
    guard let data = rep.representation(using: .png, properties: [:]) else { return }
    try? data.write(to: URL(fileURLWithPath: path))
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

// iconset 要的十档：1x/2x 成对
let pairs: [(Int, String)] = [
    (16, "icon_16x16.png"), (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"), (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"), (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"), (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"), (1024, "icon_512x512@2x.png"),
]
for (px, name) in pairs {
    writePNG(makeIcon(pixels: px), pixels: px, to: (outDir as NSString).appendingPathComponent(name))
}
print("✓ 图标已生成：\(outDir)")
