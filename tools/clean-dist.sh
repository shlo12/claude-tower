#!/bin/sh
# 清理 dist/ 里过期的分发包，只留当前版本。
#
#   默认只列出会被删的东西（不删）
#   tools/clean-dist.sh -f     真的删
#
# 只认本工具自己的命名：ClaudeTower-<版本>-macOS / -windows-src 及其 .zip。
# 别的东西一律不碰——dist/ 里可能还有你手动放进去的临时文件。
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$DIR/dist"
FORCE=0
[ "${1:-}" = "-f" ] || [ "${1:-}" = "--force" ] && FORCE=1

[ -d "$DIST" ] || { echo "dist/ 不存在，没什么可清的"; exit 0; }

VER="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$DIR/app.py" | head -n 1)"
[ -n "${VER:-}" ] || { echo "✗ 读不到 app.py 里的 VERSION"; exit 1; }
KEEP="ClaudeTower-$VER-"

# 认两种命名：新的 ClaudeTower-<版本>-<平台>，和旧的 ClaudeTower-windows-src-v<版本>
STALE="$(ls -1 "$DIST" | grep -E '^ClaudeTower-' | grep -v -F "$KEEP" || true)"
JUNK="$(ls -1 "$DIST" | grep -E '^(\.DS_Store|Claude Tower .*)$' || true)"

if [ -z "$STALE$JUNK" ]; then
  echo "✓ dist/ 里只有当前版本 ${VER}，没有可清的"
  exit 0
fi

echo "当前版本：${VER}（保留 ${KEEP}*）"
echo
if [ -n "$STALE" ]; then
  echo "过期分发包："
  echo "$STALE" | sed 's/^/  /'
fi
if [ -n "$JUNK" ]; then
  echo "旧命名残留："
  echo "$JUNK" | sed 's/^/  /'
fi
echo

if [ "$FORCE" -ne 1 ]; then
  echo "以上只是列出，没有删除。确认要删就跑：tools/clean-dist.sh -f"
  exit 0
fi

echo "$STALE" | while read -r item; do
  [ -n "$item" ] || continue
  rm -rf "$DIST/$item"
  echo "  已删 $item"
done
echo "$JUNK" | while read -r item; do
  [ -n "$item" ] || continue
  rm -rf "$DIST/$item"
  echo "  已删 $item"
done

echo
echo "✓ 清理完成，剩下："
ls -1 "$DIST" | sed 's/^/  /'
