#!/bin/sh
# 把 Windows 嵌入式 Python 放进源码包，让对方不用自己装 Python。
#
#   tools/python-runtime-win.sh <目标目录>
#
# 用的是 python.org 官方的 embeddable 包：11 MB，自带解释器和完整标准库
# （打成 python312.zip，里面是 .pyc）。它不需要安装、不写注册表，
# 解压出来就能跑——正好符合「发个压缩包给对方双击」的场景。
#
# 刻意不做裁剪：这个包本来就不大，而 Windows 那边的行为我们没法在本机验证，
# 删文件省下的几 MB 换一个「对方打不开」的风险，不划算。
set -eu

OUT="${1:-}"
[ -n "$OUT" ] || { echo "用法：tools/python-runtime-win.sh <目标目录>"; exit 1; }

DIR="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$DIR/tools/cache"
PYVER="3.12.10"
ZIPNAME="python-$PYVER-embed-amd64.zip"
URL="https://www.python.org/ftp/python/$PYVER/$ZIPNAME"

mkdir -p "$CACHE"
if [ ! -f "$CACHE/$ZIPNAME" ]; then
  echo "→ 下载 Windows 嵌入式运行时 $PYVER"
  curl -fsSL --max-time 180 -o "$CACHE/$ZIPNAME.part" "$URL" \
    || { echo "✗ 下载失败：$URL"; rm -f "$CACHE/$ZIPNAME.part"; exit 1; }
  mv "$CACHE/$ZIPNAME.part" "$CACHE/$ZIPNAME"
else
  echo "→ 使用缓存的运行时 $PYVER"
fi

rm -rf "$OUT"
mkdir -p "$OUT"
# ditto 在 macOS 上解 Windows zip 最稳；unzip 会把 CRLF 和属性弄乱
if command -v ditto >/dev/null 2>&1; then
  ditto -x -k "$CACHE/$ZIPNAME" "$OUT"
else
  unzip -q "$CACHE/$ZIPNAME" -d "$OUT"
fi

[ -f "$OUT/python.exe" ] || { echo "✗ 解压后没找到 python.exe"; exit 1; }
[ -f "$OUT/python312.zip" ] || { echo "✗ 缺少标准库 python312.zip"; exit 1; }

echo "  解释器：$(du -sh "$OUT" | cut -f1)"
