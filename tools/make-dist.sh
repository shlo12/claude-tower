#!/bin/sh
# 打一个能直接发给别人的分发包
#   产物：dist/ClaudeTower-<版本>-macOS/  以及同名 .zip
#
# 命名跟 Windows 源码包对齐（ClaudeTower-<版本>-windows-src），
# 两个包在 dist/ 里排在一起，版本号在最显眼的位置——
# 以前 macOS 叫「Claude Tower 2.8.0」、Windows 叫「ClaudeTower-windows-src-v2.9.4」，
# 一眼看不出谁新谁旧，发错版本是迟早的事。
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$DIR/app.py" | head -n 1)"
[ -n "${VER:-}" ] || { echo "✗ 读不到 app.py 里的 VERSION"; exit 1; }

NAME="ClaudeTower-$VER-macOS"
DIST="$DIR/dist"
STAGE="$DIST/$NAME"
ZIP="$DIST/$NAME.zip"

echo "→ 构建应用（通用二进制）"
"$DIR/tools/build-app.sh"

echo
echo "→ 组装分发包"
# 上一版的分发包挪走而不是删掉：这里同样是上千个文件，而且中途失败时
# 留着上一版比留一个半成品有用。清理由 tools/clean-build.sh 统一做。
if [ -e "$STAGE" ] || [ -e "$ZIP" ]; then
  TRASH="$(mktemp -d "$DIR/build/trash-dist-$(date +%Y%m%d-%H%M%S)-XXXX")"
  [ -e "$STAGE" ] && mv "$STAGE" "$TRASH/"
  [ -e "$ZIP" ] && mv "$ZIP" "$TRASH/"
  echo "  上一版分发包已移到 $TRASH"
fi
mkdir -p "$STAGE"

# ditto 才能保住签名、图标资源和扩展属性；cp -R 会把签名弄坏
ditto "$DIR/Claude Tower.app" "$STAGE/Claude Tower.app"
install -m 755 "$DIR/tools/首次打开.command" "$STAGE/① 首次打开.command"
install -m 644 "$DIR/tools/使用说明.txt"     "$STAGE/② 使用说明.txt"

# 校验：签名没被 ditto 弄坏，架构还是两个
codesign --verify --deep --strict "$STAGE/Claude Tower.app" 2>/dev/null \
  && echo "  签名校验：通过" || echo "  ⚠ 签名校验未通过（不影响本机，但对方可能要多点一次）"
lipo -info "$STAGE/Claude Tower.app/Contents/MacOS/CCclean" | sed 's/^/  /'

echo
echo "→ 压缩"
# 用 Python 打包：ditto / zip 写中文文件名时不设 UTF-8 标记位，
# 别人用第三方解压软件会看到乱码；zipfile 会自动打上标记并保住可执行权限。
PY=""
for c in /usr/bin/python3 "$(command -v python3 2>/dev/null || true)"; do
  [ -n "$c" ] && [ -x "$c" ] && { PY="$c"; break; }
done
if [ -n "$PY" ]; then
  "$PY" "$DIR/tools/pack_zip.py" "$STAGE" "$ZIP"
else
  echo "  ⚠ 没找到 python3，退回 ditto（中文文件名可能被第三方解压软件显示成乱码）"
  ditto -c -k --sequesterRsrc --keepParent "$STAGE" "$ZIP"
fi

# 自检：文件名编码标记 + 不该混进来的东西
if [ -n "$PY" ]; then
  "$PY" - "$ZIP" <<'PYEOF'
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
bad = [i.filename for i in z.infolist()
       if any(ord(ch) > 127 for ch in i.filename) and not (i.flag_bits & 0x800)]
print("  UTF-8 文件名标记：" + ("通过" if not bad else f"⚠ {len(bad)} 个未标记"))
junk = [i.filename for i in z.infolist()
        if "__pycache__" in i.filename or i.filename.endswith((".DS_Store", ".pyc"))]
if junk:
    print(f"  ⚠ 压缩包里混进了 {len(junk)} 个临时文件")
PYEOF
fi

echo
echo "✓ 完成"
du -sh "$STAGE" | awk '{print "  目录：" $1}'
du -sh "$ZIP"   | awk '{print "  压缩包：" $1}'
echo "  路径：$ZIP"

# dist/ 里留着旧版本时提醒一句：很容易把过期的那个发出去
# 同版本的另一平台包（windows-src）不算「旧版本」，所以按版本号而不是包名比
OLD="$(ls -1 "$DIST" 2>/dev/null | grep -E '^ClaudeTower-.*-(macOS|windows-src)(\.zip)?$' \
       | grep -v -F "ClaudeTower-$VER-" || true)"
if [ -n "$OLD" ]; then
  echo
  echo "  ⚠ dist/ 里还有别的版本，别发错了："
  echo "$OLD" | sed 's/^/    /'
  echo "  只留这一版可以跑：tools/clean-dist.sh"
fi
