import Cocoa
let root = URL(fileURLWithPath: CommandLine.arguments[1]).appendingPathComponent("AppIcon.iconset")
try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                  bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                  isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        let p = CGFloat(pixels)
        NSColor(calibratedRed: 0.12, green: 0.40, blue: 0.82, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: p * 0.08, y: p * 0.08, width: p * 0.84, height: p * 0.84), xRadius: p * 0.18, yRadius: p * 0.18).fill()
        if let symbol = NSImage(systemSymbolName: "tray.and.arrow.down.fill", accessibilityDescription: nil) {
            symbol.isTemplate = false
            let image = NSImage(size: NSSize(width: p, height: p))
            image.lockFocus()
            symbol.draw(in: NSRect(x: p * 0.25, y: p * 0.25, width: p * 0.5, height: p * 0.5))
            NSColor.white.setFill()
            NSRect(x: 0, y: 0, width: p, height: p).fill(using: .sourceIn)
            image.unlockFocus()
            image.draw(in: NSRect(x: 0, y: 0, width: p, height: p))
        }
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale == 2 ? "@2x" : ""
        try rep.representation(using: .png, properties: [:])!.write(to: root.appendingPathComponent("icon_\(size)x\(size)\(suffix).png"))
    }
}
