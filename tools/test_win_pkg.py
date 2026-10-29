#!/usr/bin/env python3
"""Windows 分发包的结构检查。

我们没法在 macOS 上真的双击 .bat，但可以把「对方一解压就会崩」的
那几类问题在这里拦住：运行时缺文件、标准库不全、启动器没指向内置运行时、
模块漏打、中文文件名没打 UTF-8 标记。

    python3 tools/test_win_pkg.py dist/ClaudeTower-2.9.5-windows-src.zip
    python3 tools/test_win_pkg.py dist/ClaudeTower-2.9.5-windows-src/    # 也可传目录
"""

from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# app.py 用到的标准库，缺一个就是启动即崩
NEEDED_STDLIB = [
    "http/server.pyc", "http/client.pyc", "json/__init__.pyc", "urllib/request.pyc",
    "ssl.pyc", "socket.pyc", "subprocess.pyc", "email/__init__.pyc", "mimetypes.pyc",
    "secrets.pyc", "threading.pyc", "webbrowser.pyc", "ipaddress.pyc", "base64.pyc",
]

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}" + (f"  —— {detail}" if detail else ""))


class Pkg:
    """zip 或目录，统一成「名字 → 读字节」的接口。"""

    def __init__(self, path: Path):
        self.zip = zipfile.ZipFile(path) if path.is_file() else None
        self.dir = None if self.zip else path
        if self.zip:
            self.names = set(self.zip.namelist())
            self.prefix = ""
            tops = {n.split("/", 1)[0] for n in self.names if "/" in n}
            if len(tops) == 1 and not any(n == next(iter(tops)) for n in self.names):
                self.prefix = next(iter(tops)) + "/"
        else:
            self.names = {str(p.relative_to(self.dir)).replace("\\", "/")
                          for p in self.dir.rglob("*") if p.is_file()}
            self.prefix = ""

    def has(self, rel: str) -> bool:
        return (self.prefix + rel) in self.names

    def read(self, rel: str) -> bytes:
        key = self.prefix + rel
        if self.zip:
            return self.zip.read(key)
        return (self.dir / key).read_bytes()

    def listing(self) -> list[str]:
        return sorted(n[len(self.prefix):] for n in self.names if n.startswith(self.prefix))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = Path(argv[1]).resolve()
    if not path.exists():
        print(f"✗ 找不到 {path}")
        return 1
    pkg = Pkg(path)
    print(f"检查 {path.name}")

    print("\n[1] 启动必需的文件")
    for rel in ("Claude Tower.bat", "app.py", "core/__init__.py", "web/index.html",
                "web/app.js", "web/tower.js", "web/style.css"):
        check(f"{rel} 存在", pkg.has(rel))

    print("\n[2] 内置运行时")
    for rel in ("runtime/python/python.exe", "runtime/python/python312.dll",
                "runtime/python/python312.zip", "runtime/python/python312._pth"):
        check(f"{rel} 存在", pkg.has(rel))

    pth = pkg.read("runtime/python/python312._pth").decode("utf-8", "replace")
    check("_pth 里含当前目录（否则 import 不到 app 的同级模块）",
          any(ln.strip() == "." for ln in pth.splitlines()), pth.replace("\n", " | "))

    std = zipfile.ZipFile(io.BytesIO(pkg.read("runtime/python/python312.zip")))
    names = set(std.namelist())
    missing = [m for m in NEEDED_STDLIB if m not in names]
    check("标准库够用", not missing, f"缺 {', '.join(missing)}")
    check("标准库不是空壳", len(names) > 400, f"只有 {len(names)} 项")

    print("\n[3] 启动器指向内置运行时")
    bat = pkg.read("Claude Tower.bat").decode("utf-8", "replace")
    check("优先用 runtime\\python\\python.exe", "runtime\\python\\python.exe" in bat)
    check("内置运行时缺失时退回系统 python", "where python" in bat)
    check("启动失败时不闪退", "pause" in bat)

    print("\n[4] 模块有没有漏")
    src_core = sorted(p.name for p in (ROOT / "core").glob("*.py"))
    lost = [n for n in src_core if not pkg.has(f"core/{n}")]
    check(f"core/ 下 {len(src_core)} 个模块都在", not lost, f"缺 {', '.join(lost)}")

    print("\n[5] 别把垃圾打进去")
    junk = [n for n in pkg.listing()
            if "__pycache__" in n or n.endswith(".DS_Store")
            or (n.endswith(".pyc") and not n.startswith("runtime/"))]
    check("没有缓存文件", not junk, ", ".join(junk[:4]))

    if pkg.zip:
        print("\n[6] 中文文件名标记")
        bad = [i.filename for i in pkg.zip.infolist()
               if any(ord(ch) > 127 for ch in i.filename) and not (i.flag_bits & 0x800)]
        check("非 ASCII 文件名带 UTF-8 标记", not bad, f"{len(bad)} 个未标记")

    print(f"\n{'='*46}\n  通过 {PASS} 项，失败 {FAIL} 项\n{'='*46}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
