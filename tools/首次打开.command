#!/bin/sh
# Claude Tower · 首次打开辅助脚本
# 作用：去掉 macOS 给「从网上下载的文件」打的隔离标记，然后启动应用。
# 只在第一次需要；之后直接双击应用即可。

set -u
cd "$(dirname "$0")" || exit 1

APP="Claude Tower.app"

echo "Claude Tower · 首次打开"
echo "────────────────────"
echo

if [ ! -d "$APP" ]; then
  echo "✗ 这个文件夹里没有找到「$APP」。"
  echo "  请把本脚本和「Claude Tower.app」放在同一个文件夹里再运行。"
  echo
  printf "按回车键关闭…"
  read -r _
  exit 1
fi

if xattr -p com.apple.quarantine "$APP" >/dev/null 2>&1; then
  echo "→ 解除系统对下载文件的隔离标记…"
  xattr -dr com.apple.quarantine "$APP" 2>/dev/null
fi

echo "→ 正在启动 Claude Tower…"
open "$APP"
sleep 1
echo
echo "✓ 已启动。这个终端窗口可以直接关掉。"
echo "  以后再打开，直接双击「Claude Tower.app」就行。"
