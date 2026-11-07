import CoreGraphics

/// 面板该出现在哪。
///
/// 单独抽出来是因为它没法靠「点一下看看」验证：贴左边缘、贴右边缘、屏幕比
/// 面板还窄、菜单栏图标在副屏上——这几种情况在开发机上很难凑齐，凑齐了也
/// 只有站在那台机器前的人能看到。纯函数就能把它们一个个算清楚。
///
/// 坐标系是 AppKit 的全局屏幕坐标（原点左下，y 向上）。
enum PanelGeometry {
    /// 面板四边离屏幕边缘至少留这么多。
    /// 不留的话圆角会被屏幕边缘切掉，看起来像窗口漏了一块。
    static let margin: CGFloat = 8
    /// 面板顶边离菜单栏下沿的距离。和系统弹窗的间距接近。
    static let gap: CGFloat = 6

    /// 把想要的尺寸收进屏幕可用区域。
    ///
    /// 必须单独做这一步：`origin` 只能把面板往里推，推不进去就贴着底边，
    /// 剩下的部分掉到屏幕外面——在 1440×900 的笔记本上（Dock 一大，可用高度
    /// 只剩 750 上下）窄态那 772 点就是被切掉一截，用户看到底栏少了一条。
    /// 缩高之后网页自己会压缩，「最近」那块本来就是可伸缩的。
    static func fitting(_ desired: CGSize, in visible: CGRect) -> CGSize {
        let maxWidth = max(1, visible.width - margin * 2)
        let maxHeight = max(1, visible.height - margin * 2)
        return CGSize(width: min(desired.width, maxWidth),
                      height: min(desired.height, maxHeight))
    }

    /// - Parameters:
    ///   - anchor: 菜单栏图标在屏幕坐标里的矩形。
    ///   - size: 面板尺寸（应当先经过 `fitting`）。
    ///   - visible: 屏幕可用区域（已排除菜单栏和 Dock）。
    static func origin(anchor: CGRect, size: CGSize, visible: CGRect) -> CGPoint {
        let lo = visible.minX + margin
        // 屏幕比面板还窄时 hi 会小于 lo；先抬到 lo，避免夹出一个左出界的 x。
        let hi = max(lo, visible.maxX - size.width - margin)
        let x = min(max(anchor.midX - size.width / 2, lo), hi)
        var y = anchor.minY - size.height - gap
        // 面板比可用高度还高时贴着底边，至少保证顶部内容看得见。
        if y < visible.minY + margin { y = visible.minY + margin }
        return CGPoint(x: x, y: y)
    }
}
