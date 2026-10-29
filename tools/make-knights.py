#!/usr/bin/env python3
"""生成四阶勇者像素立绘 → web/assets/knight-t{0..3}.png

经典魔塔式正面骑士：缨盔、铠甲、左盾、右立剑。
网格 16x24，x4 放大到 64x96，带 1px 轮廓光晕。
不带依赖，PNG 用 zlib+struct 手写。
"""
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "web" / "assets"
W, H, SCALE = 16, 24, 4

PAL = {
    ".": None,
    "O": (20, 24, 42),      # 轮廓
    "R": (232, 72, 63),     # 缨/亮红
    "r": (192, 56, 56),     # 盾红
    "S": (213, 224, 242),   # 银亮
    "s": (143, 163, 204),   # 银暗
    "D": (32, 38, 63),      # 面甲缝/深色
    "W": (242, 200, 160),   # 肤
    "w": (216, 168, 120),   # 肤暗
    "B": (84, 114, 200),    # 甲蓝
    "b": (58, 84, 158),     # 甲蓝暗
    "G": (238, 194, 84),    # 金
    "g": (184, 134, 46),    # 金暗
    "h": (154, 107, 60),    # 革/木
    "o": (242, 208, 107),   # 盾徽
    "d": (42, 48, 80),      # 细节深
}

# 见习 · 尖兜帽布衣（木棍）
T0 = [
    '......hh........',
    '.....hhhh.......',
    '....hhhhhhh.....',
    '...hhhhhhhhh....',
    '...hhWWWWWWh....',
    '...hWdWWWdWh..hh',
    '...hWWWWWWWh..hh',
    '...hhWWWWWWh..hh',
    '....hhhhhhhh..hh',
    '...hhhhhhhhh..hh',
    '..h.hhhhhhhh..hh',
    '..h.hhhhhhhh..hh',
    '..h.hhhhhhhh..hh',
    '....hhddddhh..hh',
    '....hhhhhhhh..hh',
    '....hh...hh...hh',
    '....hh...hh...hh',
    '....hh...hh...hh',
    '...hhh...hhh..hh',
    '................',
    '................',
    '................',
    '................',
    '................',
]

# 剑士 · 壶盔铁剑
T1 = [
    '................',
    '.....SSSSSS.....',
    '....SSSSSSSS....',
    '..SSSSSSSSSSSS..',
    '....WWWWWWWW....',
    '....WdWWWdWW..SS',
    '....WWWWWWWW..SS',
    '.....WWWWWW...SS',
    '....BBBBBBBB..SS',
    '...BBBBBBBBBB.SS',
    '..B.BBBBBBBB..SS',
    '..B.BBBBBBBB..SS',
    '..B.BBDBBBB...SS',
    '..B.BhhhhhhB..SS',
    '..B.BBBBBBBB..SS',
    '....BB....BB..SS',
    '....BB....BB..SS',
    '....BB....BB..SS',
    '....BB....BB.hhh',
    '...BBB....BBB.hh',
    '................',
    '................',
    '................',
    '................',
]

# 骑士 · 缨盔蓝甲 红盾立剑
T2 = [
    '......RRR.......',
    '.....RRRRR......',
    '......RRR.......',
    '.....SSSSSS.....',
    '....SSSSSSSS....',
    '....SDDDDDS.....',
    '....SSSSSSSS....',
    '.....SSSSSS.....',
    '.....BBBBBB.....',
    '...BBBBBBBBBB...',
    '.rR.BBBBBBBB..SS',
    'rRR.BBBBBBBB..SS',
    'roR.BBDBBBB...SS',
    'rRR.BBGGBBB...SS',
    'rRR.BBBBBBBB..SS',
    '.rR.BB...BB...SS',
    '..R.BB...BB...SS',
    '....BB...BB...SS',
    '....BB...BB..hhh',
    '...BBB...BBB..hh',
    '................',
    '................',
    '................',
    '................',
]

# 勇者 · 大缨金盔金甲 纹章盾
T3 = [
    '......RRR.......',
    '.....RRRRR......',
    '....RRRRRRR.....',
    '.....SSSSSS.....',
    '....SGGGGGGS....',
    '....SDDDDDS.....',
    '....SSSSSSS.....',
    '.....SSSSSS.....',
    '.....GGGGGG.....',
    '...GGGGGGGGGG...',
    '.rR.GGGGGGGG..SS',
    'rRR.GGgGGGGg..SS',
    'roR.GGGGGGGG..SS',
    'rRR.GGggGGG...SS',
    'rRR.GGGGGGGG..SS',
    '.rR.GG...GG...SS',
    '..R.GG...GG...SS',
    '....GG...GG...SS',
    '....GG...GG..hhh',
    '...GGG...GGG..hh',
    '................',
    '................',
    '................',
    '................',
]


def render(grid):
    assert len(grid) == H and all(len(r) == W for r in grid)
    px = [[PAL[c] for c in row] for row in grid]
    # 轮廓：透明格的 8 邻域内有实色 → 描边
    for y in range(H):
        for x in range(W):
            if px[y][x] is not None:
                continue
            hit = any(
                0 <= ny < H and 0 <= nx < W and px[ny][nx] is not None
                for ny in (y - 1, y, y + 1)
                for nx in (x - 1, x, x + 1)
                if (nx, ny) != (x, y)
            )
            if hit:
                px[y][x] = PAL["O"]
    raw = b""
    for y in range(H):
        row = b""
        for x in range(W):
            for _ in range(SCALE):
                c = px[y][x]
                row += bytes(c) + b"\xff" if c else b"\x00\x00\x00\x00"
        for _ in range(SCALE):
            raw += b"\x00" + row
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", W * SCALE, H * SCALE, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


if __name__ == "__main__":
    ROOT.mkdir(parents=True, exist_ok=True)
    for i, grid in enumerate((T0, T1, T2, T3)):
        dest = ROOT / f"knight-t{i}.png"
        dest.write_bytes(render(grid))
        print(f"✓ {dest}")
