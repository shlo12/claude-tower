#!/usr/bin/env python3
"""把分发包目录压成 zip。

为什么不用 ditto / zip：
  这两个工具写中文文件名时不会设 zip 的 UTF-8 标记位（general purpose bit 11），
  用系统的「归档实用工具」解压没问题，但别人用第三方解压软件就可能变成乱码。
  Python 的 zipfile 对非 ASCII 文件名会自动打上这个标记，同时保留可执行权限。

用法：pack_zip.py <要打包的目录> <输出 zip>
"""
import os
import sys
import zipfile


def main() -> int:
    if len(sys.argv) != 3:
        print("用法：pack_zip.py <目录> <输出.zip>", file=sys.stderr)
        return 2
    src, out = sys.argv[1], sys.argv[2]
    if not os.path.isdir(src):
        print(f"✗ 不是目录：{src}", file=sys.stderr)
        return 1

    parent = os.path.dirname(os.path.abspath(src))
    top = os.path.basename(os.path.abspath(src))
    count = 0

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        # 先把顶层目录自己写进去，解压后是一个完整文件夹，而不是散落一地
        # 目录项也用 from_file，才能带上真实的修改时间（否则会显示 1980-01-01）
        zi = zipfile.ZipInfo.from_file(src, top + "/")
        zi.external_attr = (0o40755 << 16) | 0x10
        z.writestr(zi, b"")

        for root, dirs, files in os.walk(src):
            dirs.sort()
            files.sort()
            rel = os.path.relpath(root, parent)
            if rel != top:
                zi = zipfile.ZipInfo.from_file(root, rel.replace(os.sep, "/") + "/")
                zi.external_attr = (0o40755 << 16) | 0x10
                z.writestr(zi, b"")
            for name in files:
                if name in (".DS_Store",) or name.endswith(".pyc"):
                    continue
                path = os.path.join(root, name)
                if os.path.islink(path):
                    # 符号链接在 zip 里要靠外部属性表达，解压工具支持程度不一。
                    # 与其悄悄跳过、让应用缺文件，不如直接报错。
                    print(f"✗ 不支持打包符号链接：{path}", file=sys.stderr)
                    return 1
                zi = zipfile.ZipInfo.from_file(path, os.path.relpath(path, parent))
                zi.external_attr = (os.stat(path).st_mode & 0xFFFF) << 16
                zi.compress_type = zipfile.ZIP_DEFLATED
                with open(path, "rb") as fh:
                    z.writestr(zi, fh.read())
                count += 1

    size = os.path.getsize(out)
    print(f"  {count} 个文件，{size / 1024:.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
