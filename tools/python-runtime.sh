#!/bin/sh
# 准备一个能塞进 app 包的 Python 运行时。
#
# 用法：python-runtime.sh <arm64|x86_64> <输出目录>
#
# 首次运行会从 python-build-standalone 下载对应架构的 install_only 包（约 24MB），
# 缓存在 build/python-src/<架构>/，之后不再联网。
#
# 为什么用它：macOS 12.3 起系统不再自带 Python，别人的机器上很可能一个 python3
# 都没有（/usr/bin/python3 只是个会弹「要安装命令行工具吗」的壳子）。把解释器
# 打进包体，对方才真的能做到双击就用。
#
# 为什么改成「解压时排除」而不是「先全拷再删」：
# 全量解压出来 900 多个文件，再删掉其中 800 多个。删的过程既慢又危险——
# 删错一个目录就是「启动时才崩」的那种 bug，而且任何批量删除保护都会拦下来。
# rsync 带排除规则一次成型，要什么拷什么，一个文件都不用删。
set -eu

ARCH="$1"
OUT="$2"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="$DIR/build/python-src/$ARCH"

# python-build-standalone 用 aarch64 这个名字
case "$ARCH" in
  arm64) PBS_ARCH="aarch64" ;;
  x86_64) PBS_ARCH="x86_64" ;;
  *) echo "✗ 不认识的架构：$ARCH" >&2; exit 1 ;;
esac

PBS_TAG="20261021"
PBS_VER="3.12.15"
SRC="$CACHE/python"
STAMP="$PBS_TAG-$PBS_VER-$ARCH"
STAMP_FILE="$OUT/.ccclean-runtime"

# 已经按同一版本裁好过就直接复用：重复构建时省掉一次解压 + strip
if [ -f "$STAMP_FILE" ] && [ "$(cat "$STAMP_FILE")" = "$STAMP" ] \
   && [ -x "$OUT/bin/python3.12" ]; then
  du -sh "$OUT" | awk -v a="$ARCH" '{print "  Python 运行时 " a "：" $1 "（复用）"}'
  exit 0
fi

if [ ! -d "$SRC" ]; then
  echo "  下载 Python ${PBS_VER}（${PBS_ARCH}）…"
  mkdir -p "$CACHE"
  URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/cpython-${PBS_VER}%2B${PBS_TAG}-${PBS_ARCH}-apple-darwin-install_only.tar.gz"
  TMP="$CACHE/py.tar.gz"
  curl -sSL --max-time 600 --retry 2 -o "$TMP" "$URL" \
    || { echo "✗ 下载失败，检查网络或代理：$URL" >&2; exit 1; }
  tar -xzf "$TMP" -C "$CACHE"
  rm -f "$TMP"
fi

[ -d "$SRC" ] || { echo "✗ 解压后没找到 $SRC" >&2; exit 1; }

# 目标目录里如果有上一次的残留（版本变了），先挪走而不是删掉：
# 挪到 build/trash-<时间戳>/ 下，由使用者自己决定什么时候清。
if [ -e "$OUT" ]; then
  TRASH="$DIR/build/trash-$(date +%Y%m%d-%H%M%S)-$ARCH"
  mkdir -p "$(dirname "$TRASH")"
  mv "$OUT" "$TRASH"
  echo "  旧的运行时已移到 ${TRASH}（可以手动删）"
fi
mkdir -p "$OUT"

# ---- 要什么拷什么 ----------------------------------------------------------
# 排除掉的一律不进入目标目录，所以后面不需要任何批量删除。
# GUI 工具链 / 头文件 / pkgconfig / 开发期标准库 / 用不到的动态库
# libpython3.12.dylib 有 18MB，而 bin/python3.12 是静态链接的，根本用不到。
EXCLUDES="
  --exclude=/include/
  --exclude=/share/
  --exclude=/lib/pkgconfig/
  --exclude=/lib/libtcl*
  --exclude=/lib/libtk*
  --exclude=/lib/libpython3.12.dylib
  --exclude=/lib/tcl9.0/
  --exclude=/lib/tk9.0/
  --exclude=/lib/tcl9/
  --exclude=/lib/itcl4.3.8/
  --exclude=/lib/thread3.0.6/
  --exclude=site-packages/
  --exclude=ensurepip/
  --exclude=idlelib/
  --exclude=lib2to3/
  --exclude=pydoc_data/
  --exclude=tkinter/
  --exclude=turtledemo/
  --exclude=unittest/
  --exclude=asyncio/
  --exclude=multiprocessing/
  --exclude=concurrent/
  --exclude=dbm/
  --exclude=venv/
  --exclude=test/
  --exclude=curses/
  --exclude=__pycache__/
  --exclude=*.pyc
"

# bin 里只留解释器本体：pip / idle / 2to3 / pydoc 都不需要，
# 连 python3 / python 两个符号链接也去掉——宿主程序直接调 python3.12，
# 而 zip 里带符号链接容易在解压时出岔子，少一个变量少一个坑。
# shellcheck disable=SC2086
rsync -a \
  --include=/bin/ --include=/bin/python3.12 --exclude=/bin/* \
  $EXCLUDES \
  "$SRC"/ "$OUT"/

[ -x "$OUT/bin/python3.12" ] || { echo "✗ 拷贝后没找到 bin/python3.12" >&2; exit 1; }

PYVER="$(ls "$OUT/lib" | grep -E '^python3\.[0-9]+$' | head -1)"
[ -n "$PYVER" ] || { echo "✗ 在 $OUT/lib 里找不到 pythonX.Y 目录" >&2; exit 1; }

# 二进制瘦身（去掉调试符号和局部符号，约省 2MB）
strip -x "$OUT/bin/python3.12" 2>/dev/null || true
find "$OUT/lib" -name '*.so' -type f -exec strip -x {} \; 2>/dev/null || true

echo "$STAMP" > "$STAMP_FILE"
du -sh "$OUT" | awk -v a="$ARCH" '{print "  Python 运行时 " a "：" $1}'
