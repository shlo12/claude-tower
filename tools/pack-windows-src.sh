#!/bin/bash
# Claude Tower · Windows 分发包
# 打成 zip 发给 Windows 机器，解压后双击「Claude Tower.bat」即可。
# 包里自带 Python 运行时，对方不需要安装任何东西。
set -euo pipefail
cd "$(dirname "$0")/.."
python3 tools/check_release.py --source

VER=$(python3 -c "import re;print(re.search(r'VERSION\\s*=\\s*\"([^\"]+)\"', open('app.py').read()).group(1))")
OUT="dist/ClaudeTower-${VER}-windows-src"
# 上一版挪走而不是删掉（理由同 make-dist.sh），清理由 tools/clean-build.sh 做
if [ -e "$OUT" ] || [ -e "$OUT.zip" ]; then
  TRASH="$(mktemp -d "build/trash-dist-$(date +%Y%m%d-%H%M%S)-XXXX")"
  [ -e "$OUT" ] && mv "$OUT" "$TRASH/"
  [ -e "$OUT.zip" ] && mv "$OUT.zip" "$TRASH/"
  echo "  上一版分发包已移到 $TRASH"
fi
mkdir -p "$OUT"

# 只带运行需要的：后端 + 前端 + 启动器 + 说明
cp -R app.py core web "$OUT/"
cp "Claude Tower.bat" "$OUT/"
mkdir -p "$OUT/tools"
cp tools/build-windows.bat tools/windows-使用说明.txt "$OUT/tools/" 2>/dev/null || true

# 内置运行时：对方机器上一个 Python 都没有也能双击就跑
echo "→ 内置 Python 运行时"
sh tools/python-runtime-win.sh "$OUT/runtime/python"

# 清缓存
find "$OUT" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$OUT" -name "*.pyc" -not -path "*/runtime/*" -delete 2>/dev/null || true
find "$OUT" -name ".DS_Store" -delete 2>/dev/null || true

python3 tools/pack_zip.py "$OUT" "$OUT.zip"

# 自检：少一个文件对方就启动不了，而且现象很难查
python3 tools/test_win_pkg.py "$OUT.zip" || exit 1
python3 tools/check_release.py "$OUT.zip"

echo "✓ Windows 分发包 → $OUT.zip ($(du -sh "$OUT.zip" | cut -f1))"
echo "  对方解压后双击「Claude Tower.bat」即可，不需要装 Python"
