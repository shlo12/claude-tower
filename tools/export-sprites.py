#!/usr/bin/env python3
"""把全部勇者/怪物像素图导出成 PNG 素材包，给设计师重做用。

- 勇者：直接复制 web/assets/knight-t{0..3}.png，按阶位中文名重命名
- 怪物：复刻 web/tower.js 里 sprite() 的渲染（8x8 网格 + 调色板 + tint + 罩光），
  渲染成 128x128 PNG；文件名带关卡号、怪物名、sprite 种类
- 产出：<下载目录>/claude-tower-素材包/  +  清单.md
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import tower  # noqa: E402

from PIL import Image  # noqa: E402

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "Downloads" / "claude-tower-素材包"
SIZE = 128  # 8x8 网格放大到 128x128

# 与 web/tower.js SPRITES 一一对应（8x8 网格）
SPRITES = {
    "ghost": ['..####..', '.######.', '##o##o##', '########', '########', '########', '#.#..#.#', '........'],
    "slime": ['........', '..####..', '.######.', '##o##o##', '########', '########', '########', '.######.'],
    "puppet": ['..#..#..', '..#..#..', '.######.', '#.o##o.#', '..####..', '.######.', '..#..#..', '..#..#..'],
    "statue": ['..####..', '..#oo#..', '..####..', '.######.', '.#+##+#.', '.######.', '..####..', '.######.'],
    "imp": ['#......#', '##....##', '..####..', '.#o##o#.', '..####..', '.######.', '..#..#..', '.#....#.'],
    "echo": ['...##...', '..#oo#..', '.#o##o#.', '#o####o#', '#o####o#', '.#o##o#.', '..#oo#..', '...##...'],
    "warden": ['..####..', '.#o##o#.', '..####..', '##.##.##', '##.##.##', '########', '..####..', '.######.'],
    "shade": ['..####..', '.#oooo#.', '#.o##o.#', '#.####.#', '#.####.#', '#.####.#', '.######.', '..#..#..'],
    "sentinel": ['########', '#......#', '#..oo..#', '#..oo..#', '#......#', '########', '..####..', '.######.'],
    "merchant": ['..####..', '.######.', '#.o##o.#', '#.####.#', '.######.', '#.####.#', '..#..#..', '.######.'],
    "taxman": ['.######.', '#......#', '.#o##o#.', '..####..', '.######.', '#.####.#', '..#..#..', '.#....#.'],
    "colossus": ['##....##', '########', '##o##o##', '########', '########', '########', '##.##.##', '##....##'],
    "pipe": ['..####..', '.#+##+#.', '#..##..#', '#..##..#', '#..##..#', '.#+##+#.', '..####..', '..####..'],
    "eye": ['........', '..####..', '.#oooo#.', '#oo##oo#', '#oo##oo#', '.#oooo#.', '..####..', '........'],
    "mage": ['...##...', '..####..', '.######.', '..o##o..', '..####..', '.######.', '#.####.#', '..#..#..'],
    "mirror": ['.######.', '#++++++#', '#+#oo#+#', '#+#oo#+#', '#++++++#', '.######.', '..####..', '.######.'],
    "notary": ['..####..', '.#o##o#.', '..####..', '.######.', '##.##.##', '##.##.##', '..####..', '.######.'],
    "demon": ['#......#', '##....##', '..o##o..', '..####..', '.######.', '#.####.#', '..#..#..', '.#....#.'],
    "fog": ['........', '..####..', '.#+##+#.', '#+####+#', '#+####+#', '.#+##+#.', '..####..', '........'],
    "wraith": ['...##...', '..#oo#..', '.#o##o#.', '.######.', '.#.##.#.', '..####..', '.#.##.#.', '#..##..#'],
    "claude": ['#..##..#', '.#.##.#.', '..####..', '########', '########', '..####..', '.#.##.#.', '#..##..#'],
}


def hex_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip('#')
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def tint_of(tint: str, f: float) -> tuple[int, int, int]:
    r, g, b = hex_rgb(tint)
    return (min(255, round(r * f)), min(255, round(g * f)), min(255, round(b * f)))


def palette(kind: str, tint: str) -> dict[str, tuple[int, int, int] | None]:
    base = hex_rgb(tint)
    return {
        '.': None,
        'o': hex_rgb('#ffe9a8'),          # 眼睛
        '+': tint_of(tint, 1.55),          # 提亮
        's': hex_rgb('#dfe8ff'),
        'g': hex_rgb('#e8b64f'),
        'h': hex_rgb('#a8762a'),
        'r': hex_rgb('#e05252'),
        'd': hex_rgb('#232a47'),
        'w': hex_rgb('#f2d8b0'),
        '#': base,
    }


def render_sprite(kind: str, tint: str, size: int = SIZE) -> Image.Image:
    grid = SPRITES[kind]
    pal = palette(kind, tint)
    cell = size // 8
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    px = img.load()
    for y, row in enumerate(grid):
        for x, ch in enumerate(row):
            color = pal.get(ch)
            if color is None:
                continue
            for dy in range(cell):
                for dx in range(cell):
                    px[x * cell + dx, y * cell + dy] = (*color, 255)
    # 罩光：与 JS 一致——顶部白 .16 → 40% 透明 → 62% 黑 0 → 底 .36
    ov = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    opx = ov.load()
    for y in range(size):
        t = y / (size - 1)
        if t <= 0.4:
            a = int(0.16 * 255 * (1 - t / 0.4))
            c = (255, 255, 255)
        elif t <= 0.62:
            a = 0
            c = (0, 0, 0)
        else:
            a = int(0.36 * 255 * ((t - 0.62) / 0.38))
            c = (0, 0, 0)
        for x in range(size):
            opx[x, y] = (*c, a)
    img.alpha_composite(ov)
    return img


def main() -> None:
    hero_dir = OUT / "勇者"
    mob_dir = OUT / "怪物"
    hero_dir.mkdir(parents=True, exist_ok=True)
    mob_dir.mkdir(parents=True, exist_ok=True)

    tiers = ['布衣勇者', '铁盔剑士', '缨盔骑士', '传说勇者']
    manifest = ["# Claude Tower · 像素素材清单", "",
                "## 勇者（4 阶，按击杀数升阶）", "",
                "| 文件 | 阶位 | 触发条件 |", "| --- | --- | --- |"]
    for i, name in enumerate(tiers):
        src = ROOT / "web" / "assets" / f"knight-t{i}.png"
        dst = hero_dir / f"勇者-t{i}-{name}.png"
        shutil.copy(src, dst)
        manifest.append(f"| {dst.name} | t{i} {name} | 击杀 ≥ {[0, 1, 5, 10][i]} |")

    manifest += ["", "## 怪物（29 小关 + 4 层主 + 1 塔主）", "",
                 "| 文件 | 关卡 | 怪物名 | 精灵种类 | 主题色 |", "| --- | --- | --- | --- | --- |"]

    def emit(fname: str, title: str, name: str, kind: str, tint: str):
        img = render_sprite(kind, tint)
        img.save(mob_dir / fname)
        manifest.append(f"| {fname} | {title} | {name} | {kind} | {tint} |")

    for f in tower.FLOORS:
        for lv in f["levels"]:
            m = lv["monster"]
            emit(f"{lv['id']}_{lv['title']}_{m['name']}_{m['kind']}.png",
                 lv["id"] + " " + lv["title"], m["name"], m["kind"], m["tint"])
        b = f.get("boss")
        if b and f["id"] != "f5":
            emit(f"{f['id']}-层主_{b['name']}_{b['kind']}.png",
                 f"第{f['no']}层 层主", b["name"], b["kind"], b["tint"])
        if f["id"] == "f5" and b:
            emit(f"塔顶_最终BOSS_{b['name']}_{b['kind']}.png",
                 "塔顶 最终BOSS", b["name"], b["kind"], b["tint"])

    (OUT / "清单.md").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    print(f"✓ 素材包 → {OUT}")
    print(f"  勇者 {len(list(hero_dir.glob('*.png')))} 张 / 怪物 {len(list(mob_dir.glob('*.png')))} 张")


if __name__ == "__main__":
    main()
