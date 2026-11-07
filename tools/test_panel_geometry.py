#!/usr/bin/env python3
"""面板落点：编译真实的 PanelGeometry，在各种屏幕/图标位置下算一遍。

为什么值得单独测：贴边、副屏、屏幕比面板还窄这几种情况，开发机上很难凑齐；
凑齐了也只有坐在那台机器前的人能看见。算错了的表现是「面板跑到屏幕外」或
「圆角被切掉」，用户第一反应是「这软件坏了」，而我们自己复现不出来。

    python3 tools/test_panel_geometry.py
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HARNESS = r'''
import Foundation
func ok(_ v: Bool, _ why: String) { if !v { fatalError(why) } }

let panel = CGSize(width: 340, height: 772)
// 主屏：1440 宽，菜单栏占掉顶部 25，Dock 占掉底部 60。
let visible = CGRect(x: 0, y: 60, width: 1440, height: 900 - 60 - 25)
// 图标在右上角，宽 28、高 24，贴在菜单栏里。
let rightIcon = CGRect(x: 1400, y: visible.maxY, width: 28, height: 24)

// 1. 常见情况：图标靠右，面板应该往左让，右边不越界。
var p = PanelGeometry.origin(anchor: rightIcon, size: panel, visible: visible)
ok(p.x + panel.width <= visible.maxX, "right edge must stay on screen")
ok(p.x >= visible.minX, "left edge must stay on screen")
ok(p.y + panel.height <= rightIcon.minY, "panel must sit below the icon")
ok(rightIcon.minY - (p.y + panel.height) <= PanelGeometry.gap + 0.5, "gap should be tight")

// 2. 图标在正中间：面板应该水平居中于图标。
let centerIcon = CGRect(x: 700, y: visible.maxY, width: 28, height: 24)
p = PanelGeometry.origin(anchor: centerIcon, size: panel, visible: visible)
ok(abs((p.x + panel.width / 2) - centerIcon.midX) < 0.5, "should centre under the icon")

// 3. 图标贴左边缘：面板不能被推出去。
let leftIcon = CGRect(x: 0, y: visible.maxY, width: 28, height: 24)
p = PanelGeometry.origin(anchor: leftIcon, size: panel, visible: visible)
ok(p.x >= visible.minX + PanelGeometry.margin - 0.5, "left edge must keep the margin")

// 4. 屏幕比面板还窄（分屏、竖屏旋转后的小窗口）：宁可贴左，也不能出现负坐标。
let narrow = CGRect(x: 0, y: 60, width: 320, height: 700)
p = PanelGeometry.origin(anchor: CGRect(x: 150, y: narrow.maxY, width: 28, height: 24),
                         size: panel, visible: narrow)
ok(p.x >= narrow.minX, "narrow screen must not push the panel off the left edge")
ok(p.x == narrow.minX + PanelGeometry.margin, "narrow screen should hug the margin")

// 5. 屏幕可用高度比面板还矮：面板顶边不能跑到菜单栏里，底部允许超出。
let short = CGRect(x: 0, y: 0, width: 1440, height: 600)
p = PanelGeometry.origin(anchor: CGRect(x: 900, y: short.maxY, width: 28, height: 24),
                         size: panel, visible: short)
ok(p.y == short.minY + PanelGeometry.margin, "tall panel should anchor to the bottom margin")

// 6. 副屏在左边，坐标是负的：所有判断都得按传入的 visible 走，不能假设原点为 0。
let secondary = CGRect(x: -1920, y: 0, width: 1920, height: 1080)
p = PanelGeometry.origin(anchor: CGRect(x: -60, y: secondary.maxY, width: 28, height: 24),
                         size: panel, visible: secondary)
ok(p.x + panel.width <= secondary.maxX, "secondary screen right edge")
ok(p.x >= secondary.minX, "secondary screen left edge")

// 7. 屏幕放得下：尺寸一点都不能改，否则宽态/窄态会在好屏幕上莫名其妙变小。
var fit = PanelGeometry.fitting(panel, in: visible)
ok(fit.width == panel.width, "fitting must not shrink when it fits")
ok(fit.height == panel.height, "fitting must not shrink height when it fits")

// 8. 屏幕可用高度不够（1440×900 + 大 Dock 只剩 750）：高度要收到边距以内，
//    这样底栏才在屏幕里。收过之后 origin 必须把面板完整放进 visible。
let laptop = CGRect(x: 0, y: 60, width: 1440, height: 690)
fit = PanelGeometry.fitting(panel, in: laptop)
ok(fit.height == laptop.height - PanelGeometry.margin * 2, "height should be clamped to the visible area")
ok(fit.width == panel.width, "width is fine, must stay")
p = PanelGeometry.origin(anchor: CGRect(x: 900, y: laptop.maxY, width: 28, height: 24),
                         size: fit, visible: laptop)
ok(p.y >= laptop.minY + PanelGeometry.margin - 0.5, "clamped panel must stay above the bottom edge")
ok(p.y + fit.height <= laptop.maxY, "clamped panel must not stick out the top")

// 9. 屏幕比面板还窄：宽度也要收，不能只收高度。
let tiny = CGRect(x: 0, y: 0, width: 300, height: 400)
fit = PanelGeometry.fitting(panel, in: tiny)
ok(fit.width == tiny.width - PanelGeometry.margin * 2, "width should be clamped on a tiny screen")
ok(fit.height == tiny.height - PanelGeometry.margin * 2, "height should be clamped on a tiny screen")

// 10. 退化的 visible（0 高，比如显示器正在切换分辨率）：不能算出 0 或负数，
//     否则 NSWindow.setFrame 会拿到非法尺寸。
fit = PanelGeometry.fitting(panel, in: CGRect(x: 0, y: 0, width: 0, height: 0))
ok(fit.width >= 1 && fit.height >= 1, "degenerate visible frame must not produce a zero size")

print("panel geometry: 10 cases passed")
'''

class PanelGeometryTests(unittest.TestCase):
    def test_actual_swift_geometry(self):
        with tempfile.TemporaryDirectory() as d:
            main = Path(d) / "main.swift"
            main.write_text(HARNESS)
            binary = Path(d) / "test"
            result = subprocess.run(
                ["swiftc", str(ROOT / "shield/PanelGeometry.swift"), str(main), "-o", str(binary)],
                capture_output=True, text=True, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
