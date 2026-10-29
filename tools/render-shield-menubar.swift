import AppKit

// 把菜单栏盾牌的四种状态画成一张对照图，用来肉眼核对形状和配色。
//
// 图标本身是代码画的（shield/ShieldIcon.swift），这里只负责摆版面——
// 和 App 里跑的是同一份绘制代码，不是「照着画一遍」的仿制品。
//
//   swiftc -O shield/ShieldIcon.swift tools/render-shield-menubar.swift \
//     -o build/render-menubar
//   build/render-menubar build/preview/menubar-icons.png
//
// 多文件编译时 Swift 只允许 main.swift 里写顶层语句，所以这里套一层 @main。

@main
struct RenderMenubarIcons {

    static let states: [(ShieldIconState, String)] = [
        (.idle, "idle 待命"),
        (.safe, "safe 守护中"),
        (.warn, "warn 出口存疑"),
        (.danger, "danger 出口已断"),
    ]

    /// 菜单栏的两种底色。浅色取 #ededed 附近，深色取 #2b2b2b 附近。
    static let bgs: [(bg: NSColor, name: String, ink: NSColor)] = [
        (NSColor(calibratedWhite: 0.93, alpha: 1), "浅色菜单栏",
         NSColor(calibratedWhite: 0.20, alpha: 1)),
        (NSColor(calibratedWhite: 0.17, alpha: 1), "深色菜单栏",
         NSColor(calibratedWhite: 0.92, alpha: 1)),
    ]

    /// 在 rect 里按矢量重画一遍，而不是把 18pt 的位图放大——放大只能看到
    /// 锯齿，看不出形状。
    ///
    /// 必须先画进一张独立的透明图层再合成：`ShieldIcon.cut()` 用的是
    /// `.clear`，直接画在底色上会把底色一起擦掉，挖出来的缺口会变成
    /// 透明（看图时显示成白色），看起来像根本没挖。
    static func drawIcon(_ state: ShieldIconState, in rect: NSRect, ink: NSColor) {
        let layer = NSImage(size: rect.size, flipped: false) { r in
            let t = NSAffineTransform()
            t.scale(by: r.width / ShieldIcon.size.width)
            t.concat()
            ShieldIcon.draw(state, ink: ink)
            return true
        }
        layer.draw(in: rect)
    }

    static func main() {
        let args = CommandLine.arguments
        // 默认落到 build/preview/（被 .gitignore 收着）。之前默认写当前目录，
        // 随手跑一次就在仓库根上留一张图，git status 里多一条未跟踪。
        let outPath = args.count > 1 ? args[1] : "build/preview/menubar-icons.png"
        try? FileManager.default.createDirectory(
            atPath: (outPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)

        let cellW: CGFloat = 108
        let cellH: CGFloat = 132
        let pad: CGFloat = 16
        let W = pad * 2 + cellW * CGFloat(states.count)
        // 最后一条是「真实尺寸」模拟菜单栏：24pt 高，图标按 18pt 原样摆。
        // 4 倍放大只能看形状，看不出「缩到菜单栏里还认不认得出」——
        // 上一版就是被放大图骗过去的：4 倍下清楚，真机上是一根头发丝。
        let stripH: CGFloat = 24
        let H = pad * 2 + cellH * CGFloat(bgs.count) + stripH + 14

        // 2x 位图：菜单栏本来就是 Retina 渲染的，1x 截图看不出锯齿
        let pxW = Int(W * 2)
        let pxH = Int(H * 2)
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pxW,
                                         pixelsHigh: pxH, bitsPerSample: 8,
                                         samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                         colorSpaceName: .deviceRGB, bytesPerRow: 0,
                                         bitsPerPixel: 0) else {
            print("✗ 位图创建失败")
            exit(1)
        }
        rep.size = NSSize(width: W, height: H)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

        let label: [NSAttributedString.Key: Any] = [
            .font: NSFont.systemFont(ofSize: 9, weight: .medium),
            .foregroundColor: NSColor(calibratedWhite: 0.55, alpha: 1),
        ]

        for (row, bg) in bgs.enumerated() {
            // 两行大图从底部「真实尺寸条」上方开始，别压到条上
            let y = H - pad - cellH * CGFloat(row + 1)
            for (col, st) in states.enumerated() {
                let x = pad + cellW * CGFloat(col)
                let cell = NSRect(x: x, y: y, width: cellW, height: cellH)

                bg.bg.setFill()
                cell.fill()
                bg.ink.setStroke()
                let edge = NSBezierPath(rect: cell.insetBy(dx: 0.5, dy: 0.5))
                edge.lineWidth = 0.5
                edge.stroke()

                // template 的两种按主题上色，上色的两种用自己的颜色
                let ink = ShieldIcon.isTemplate(st.0) ? bg.ink : NSColor.black

                // 上面放 4 倍大的看形状，下面按 18pt 原尺寸看还认不认得出
                drawIcon(st.0, in: NSRect(x: cell.midX - 36, y: cell.maxY - 20 - 72,
                                          width: 72, height: 72), ink: ink)
                drawIcon(st.0, in: NSRect(x: cell.midX - 9, y: cell.minY + 26,
                                          width: 18, height: 18), ink: ink)

                let text = NSAttributedString(string: st.1, attributes: label)
                text.draw(at: NSPoint(x: cell.midX - text.size().width / 2,
                                      y: cell.minY + 9))
            }
        }

        // ---- 真实尺寸条：左半浅色、右半深色，四种图标按 18pt 摆一遍 ----
        let stripY = pad
        let half = W / 2
        let light = NSRect(x: 0, y: stripY, width: half, height: stripH)
        let dark = NSRect(x: half, y: stripY, width: W - half, height: stripH)
        NSColor(calibratedWhite: 0.93, alpha: 1).setFill()
        light.fill()
        NSColor(calibratedWhite: 0.17, alpha: 1).setFill()
        dark.fill()

        for (i, st) in states.enumerated() {
            let slotL = light.minX + light.width / 4 * (CGFloat(i) + 0.5)
            let slotD = dark.minX + dark.width / 4 * (CGFloat(i) + 0.5)
            drawIcon(st.0, in: NSRect(x: slotL - 9, y: stripY + (stripH - 18) / 2,
                                      width: 18, height: 18),
                     ink: NSColor(calibratedWhite: 0.20, alpha: 1))
            drawIcon(st.0, in: NSRect(x: slotD - 9, y: stripY + (stripH - 18) / 2,
                                      width: 18, height: 18),
                     ink: NSColor(calibratedWhite: 0.92, alpha: 1))
        }
        NSAttributedString(string: "真实尺寸（左浅色 / 右深色菜单栏）", attributes: label)
            .draw(at: NSPoint(x: pad, y: stripY + stripH + 2))

        NSGraphicsContext.restoreGraphicsState()

        guard let data = rep.representation(using: .png, properties: [:]) else {
            print("✗ PNG 编码失败")
            exit(1)
        }
        try? FileManager.default.createDirectory(
            atPath: (outPath as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)
        try? data.write(to: URL(fileURLWithPath: outPath))
        print("✓ 菜单栏图标对照图：\(outPath)  (\(pxW)×\(pxH))")
    }
}
