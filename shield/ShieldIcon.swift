import AppKit

/// 菜单栏盾牌的四种样子。
///
/// 和 Probe 的 `Verdict` 分开是有意的：Verdict 说的是「现在守得怎么样」，
/// 而图标要回答的是「现在有没有问题」——Claude 没在跑的时候 verdict 是
/// `idle`，这个信息不足以决定画什么，得再看 `idleState`。
enum ShieldIconState {
    /// 待命：空心盾。没在守——暂停中、开关关了、没有塔的基线、基线过期。
    case idle
    /// 正常：实心盾 + 对勾。守护中，或者环境就绪只差启动 Claude。
    case safe
    /// 存疑：橙底 + 感叹号。出口存疑、DNS 没接管、UDP 分裂、环境被堵住。
    case warn
    /// 已断：红底 + 叉。Claude 在跑，但没有任何出口。
    case danger
}

/// 菜单栏图标。
///
/// 盾形是仓库自己的「直角五边形」：平顶、两侧竖直落到底部一半、再 45° 收到
/// 尖。面板标题旁的品牌标记（shield.css 的 `.mark`）就是这个形状，菜单栏和
/// 面板必须像同一个程序。1.6.4 试过系统 `shield.fill`，被要求「做回以前的
/// 样式」——圆肩的系统盾和面板不是一套视觉。仓库里仍然不放图片素材：
/// 形状由代码画，颜色和符号也是。
///
/// 四种状态刻意分成两组：不上色的空心 / 实心（待命、正常），上色的橙 / 红
/// （存疑、已断）。只靠颜色区分对色盲不友好，所以组内形状也不一样——
/// 对勾、感叹号、叉，缩到 18pt 也分得出来。
enum ShieldIcon {

    /// 画布 18×18。菜单栏高 24，上下各留 3。
    static let size = NSSize(width: 18, height: 18)

    /// 盾面 14.2×15.4：平顶 16.6、直角肩、两侧竖直到 8.6（占 52%），
    /// 再 45° 收到 1.2 的尖。和 1.6.1 之前那枚是同一个五边形，只是从
    /// 11pt 宽放到 14.2pt——那一版在菜单栏里糊成一团，问题在尺寸不在形状。
    static func shieldPath() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 1.9, y: 16.6))
        p.line(to: NSPoint(x: 16.1, y: 16.6))
        p.line(to: NSPoint(x: 16.1, y: 8.6))
        p.line(to: NSPoint(x: 9.0, y: 1.2))
        p.line(to: NSPoint(x: 1.9, y: 8.6))
        p.close()
        p.lineJoinStyle = .miter
        return p
    }

    /// 空心版的内边界：`shieldPath` 整体向内缩 1.9pt。
    ///
    /// 空心盾不直接描边：盾尖的内角只有 87.6°，miter 沿角平分线往外伸
    /// 1.37pt，而盾尖离画布底只剩 1.2pt——描出来的尖会被裁掉一截。填实心
    /// 再挖掉这一圈，外轮廓和实心盾严丝合缝，四角也仍是直角。
    static func hollowPath() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 3.8, y: 14.7))
        p.line(to: NSPoint(x: 14.2, y: 14.7))
        p.line(to: NSPoint(x: 14.2, y: 9.36))
        p.line(to: NSPoint(x: 9.0, y: 3.94))
        p.line(to: NSPoint(x: 3.8, y: 9.36))
        p.close()
        p.lineJoinStyle = .miter
        return p
    }

    /// 直接取面板状态卡的两个颜色（shield.css 的 `.state[data-v=...]`）：
    /// 存疑是 `--gold`、已断是 `--critical`。菜单栏说「金」、点开面板也必须是
    /// 同一个金，否则像两个程序。
    ///
    /// 别拿 `--high` 来当存疑色——那是 Tower 的严重度色阶（critical/high/
    /// medium/low），面板的状态卡一次都没用过它，混用会让「状态」和「严重度」
    /// 两套语义串在一起。
    static let warnColor = NSColor(calibratedRed: 0.878, green: 0.706, blue: 0.361, alpha: 1)   // #e0b45c
    static let dangerColor = NSColor(calibratedRed: 0.878, green: 0.322, blue: 0.322, alpha: 1) // #e05252

    /// 金色 / 红色盾面上的符号用墨迹画，不挖空。
    ///
    /// 挖空透上来的是菜单栏底色：浅色栏接近白，金子 `#e0b45c` 对白的对比只有
    /// 1.7:1，缩到菜单栏后「!」就是一片浅色缝，读不出来。深墨压在金底上约
    /// 9:1、压在红底上约 8:1，而且不随菜单栏明暗变化——像路牌，黑符号配黄牌。
    static let glyphInk = NSColor(calibratedRed: 0.13, green: 0.10, blue: 0.04, alpha: 1) // #211a0a

    /// template 只能跟着菜单栏明暗走，带不了颜色。所以只有不上色的两种
    /// 状态能开；上色的两种必须关掉，否则系统会把橙色也涂成灰白。
    static func isTemplate(_ state: ShieldIconState) -> Bool {
        state == .idle || state == .safe
    }

    static func image(_ state: ShieldIconState) -> NSImage {
        let img = NSImage(size: size, flipped: false) { _ in
            draw(state)
            return true
        }
        img.isTemplate = isTemplate(state)
        return img
    }

    /// `ink` 只对两种不上色的状态有效：template 模式下系统会把整张图染成
    /// 黑或白，渲染工具要自己模拟这件事，所以留一个入口。
    static func draw(_ state: ShieldIconState, ink: NSColor = .black) {
        switch state {
        case .idle:
            // 空心：一眼看出「没在守」，但不像告警那样抢注意力。
            ink.setFill()
            shieldPath().fill()
            cut(hollowPath(), width: nil)
        case .safe:
            ink.setFill()
            shieldPath().fill()
            cut(checkPath(), width: 2.35)
        case .warn:
            warnColor.setFill()
            shieldPath().fill()
            glyphInk.setFill()
            exclaimPath().fill()
        case .danger:
            dangerColor.setFill()
            shieldPath().fill()
            glyphInk.setStroke()
            let cross = crossPath()
            cross.lineWidth = 2.35
            cross.lineCapStyle = .round
            cross.stroke()
        }
    }

    /// 对勾。0.94 缩放后端点 6.18,10.32 → 8.44,7.87 → 12.67,12.57。
    /// 两个端点都落在竖直边那一段：20x 回读离右边最近 2.25pt，离左边 4.3pt。
    static func checkPath() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 6.18, y: 10.32))
        p.line(to: NSPoint(x: 8.44, y: 7.87))
        p.line(to: NSPoint(x: 12.67, y: 12.57))
        return p
    }

    /// 感叹号：3.4pt 宽的圆角竖条 + 3.2pt 圆点，用深墨画在金底上。
    ///
    /// 1.6.4 的 3.95pt 版本是配系统盾的圆肩的；直角盾的 V 更窄，同尺寸的
    /// 点压到 2.6 会伸出斜边，所以整体上移、收窄。
    ///
    /// 挖空版读不出来不是宽度问题：挖空透出的是浅色菜单栏，金底对浅底
    /// 只有 1.7:1。改成墨迹后 2x 下竖条和点都约 6px，对比约 9:1；
    /// 20x 回读离 V 的斜边最近 2.53pt。
    static func exclaimPath() -> NSBezierPath {
        let p = NSBezierPath(roundedRect: NSRect(x: 7.3, y: 9.5, width: 3.4, height: 4.0),
                             xRadius: 1.5, yRadius: 1.5)
        p.appendOval(in: NSRect(x: 7.4, y: 5.6, width: 3.2, height: 3.2))
        return p
    }

    /// 叉。和感叹号的轮廓差得够远，不靠颜色也分得开。
    /// 0.94 缩放后端点 6.37..11.44 / 7.62..12.70，线宽 2.35。
    /// 比 1.6.4 整体上移 0.5：下面的两个圆头原本压到 V 的斜边上；
    /// 上移后 20x 回读离斜边最近 1.36pt。
    static func crossPath() -> NSBezierPath {
        let p = NSBezierPath()
        p.move(to: NSPoint(x: 6.37, y: 12.70))
        p.line(to: NSPoint(x: 11.44, y: 7.62))
        p.move(to: NSPoint(x: 11.44, y: 12.70))
        p.line(to: NSPoint(x: 6.37, y: 7.62))
        return p
    }

    /// 在实心盾上挖掉一块：宽度给了就描边挖，没给就整块挖。
    ///
    /// template 模式下颜色不参与渲染、只有 alpha 算数，所以对勾和空心的
    /// 内圈必须是透明的洞；上色的两种能画墨迹，就不该挖空——洞透出的是
    /// 菜单栏底色，浅色栏上金底/浅底对比太低（见 `glyphInk`）。
    private static func cut(_ path: NSBezierPath, width: CGFloat?) {
        guard let ctx = NSGraphicsContext.current else { return }
        ctx.saveGraphicsState()
        ctx.compositingOperation = .clear
        NSColor.white.set()
        if let w = width {
            path.lineWidth = w
            path.lineCapStyle = .round
            path.lineJoinStyle = .round
            path.stroke()
        } else {
            path.fill()
        }
        ctx.restoreGraphicsState()
    }
}
