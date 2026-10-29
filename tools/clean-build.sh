#!/bin/sh
# 清掉构建残留。构建脚本现在不再自己删东西，而是把旧的挪到 build/trash-*，
# 所以这里统一收尾：
#
#   tools/clean-build.sh          列出会删什么
#   tools/clean-build.sh -f       真的删
#
# 只碰 build/ 下的中间产物和项目根目录的 Claude Tower.app，不动别的东西。
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build"
APP="$DIR/Claude Tower.app"
FORCE=0
[ "${1:-}" = "-f" ] || [ "${1:-}" = "--force" ] && FORCE=1

TARGETS=""
for p in "$BUILD"/trash-* "$BUILD"/AppIcon.iconset "$BUILD"/AppIcon.iconset.old \
         "$BUILD"/py-arm64 "$BUILD"/py-x86_64; do
  [ -e "$p" ] && TARGETS="$TARGETS$p
"
done

if [ -z "$TARGETS" ] && [ ! -e "$APP" ]; then
  echo "✓ 没有构建残留"
  exit 0
fi

[ -n "$TARGETS" ] && printf '%s' "$TARGETS" | sed 's/^/  /'
[ -e "$APP" ] && echo "  ${APP}（已构建的应用，删掉不影响源码）"

if [ "$FORCE" -ne 1 ]; then
  echo
  echo "以上只是列出，没有删除。确认要删就跑：tools/clean-build.sh -f"
  exit 0
fi

printf '%s' "$TARGETS" | while IFS= read -r p; do
  [ -n "$p" ] || continue
  rm -rf "$p"
  echo "  已删 $(basename "$p")"
done
[ -e "$APP" ] && { rm -rf "$APP"; echo "  已删 Claude Tower.app"; }
echo "✓ 清理完成"
