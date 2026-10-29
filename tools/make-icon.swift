import AppKit

let args = CommandLine.arguments
let outDir = args.count > 1 ? args[1] : "./AppIcon.iconset"
let artPath = args.count > 2 ? args[2] : "./tools/app-icon.png"

guard let art = NSImage(contentsOfFile: artPath) else {
    FileHandle.standardError.write("✗ 读不到图标源图：\(artPath)\n".data(using: .utf8)!)
    exit(1)
}

func makeIcon(pixels: Int) -> NSImage {
    let size = CGFloat(pixels)
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()
    NSGraphicsContext.current?.imageInterpolation = .high

    let inset = size * 0.085
    let bgRect = NSRect(x: inset, y: inset, width: size - inset * 2, height: size - inset * 2)
    let radius = size * 0.225
    let bg = NSBezierPath(roundedRect: bgRect, xRadius: radius, yRadius: radius)

    NSGraphicsContext.saveGraphicsState()
    bg.addClip()
    art.draw(in: bgRect, from: .zero, operation: .sourceOver, fraction: 1,
             respectFlipped: false, hints: [.interpolation: NSImageInterpolation.high])
    // 极细的一圈内高光，让深色图标在深色 Dock 上仍有边界
    let edge = NSBezierPath(roundedRect: bgRect.insetBy(dx: 0.5, dy: 0.5),
                            xRadius: radius * 0.97, yRadius: radius * 0.97)
    edge.lineWidth = max(1, size * 0.003)
    NSColor(calibratedWhite: 1, alpha: 0.10).setStroke()
    edge.stroke()
    NSGraphicsContext.restoreGraphicsState()

    img.unlockFocus()
    return img
}

func writePNG(_ img: NSImage, pixels: Int, to path: String) {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    ) else { return }
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    img.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
    NSGraphicsContext.restoreGraphicsState()
    if let data = rep.representation(using: .png, properties: [:]) {
        try? data.write(to: URL(fileURLWithPath: path))
    }
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

let variants: [(String, Int)] = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]

for (name, px) in variants {
    writePNG(makeIcon(pixels: px), pixels: px, to: outDir + "/" + name)
}
print("iconset written to \(outDir)")
