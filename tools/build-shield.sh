#!/bin/sh
# 构建 Claude Shield.app（菜单栏常驻的哨兵）
#
# 和 Claude Tower 不同，Shield 不内嵌 Python：巡检就是读进程表、路由表和
# 系统代理开关，原生几百行就够，冷启动也是瞬间的。
#
# 用法：
#   tools/build-shield.sh                     # 单独构建到仓库根目录
#   tools/build-shield.sh <输出 .app 路径>    # build-app.sh 用来嵌进 Tower
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build"
APP="${1:-$DIR/Claude Shield.app}"
CONTENTS="$APP/Contents"

echo "→ 清理旧构建"
# 同 build-app.sh：先挪走再重建，中途失败时上一版还在
if [ -e "$APP" ]; then
  TRASH="$(mktemp -d "$BUILD/trash-shield-$(date +%Y%m%d-%H%M%S)-XXXX")"
  mv "$APP" "$TRASH/"
  echo "  上一版已移到 $TRASH"
fi
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources" "$BUILD"

echo "→ 生成图标"
swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. "$DIR/tools/make-shield-icon.swift" -o "$BUILD/make-shield-icon" >/dev/null 2>&1
"$BUILD/make-shield-icon" "$BUILD/Shield.iconset" >/dev/null
iconutil -c icns "$BUILD/Shield.iconset" -o "$CONTENTS/Resources/AppIcon.icns"

echo "→ 编译宿主程序（arm64 + x86_64 通用）"
# 部署目标同 Tower：11.0，覆盖 Big Sur / Monterey
for arch in arm64 x86_64; do
  swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. -target "$arch-apple-macosx11.0" -framework Cocoa -framework WebKit \
    "$DIR/shield/Probe.swift" "$DIR/shield/Store.swift" "$DIR/shield/TzFix.swift" \
    "$DIR/shield/Watchdog.swift" "$DIR/shield/ShieldIcon.swift" \
    "$DIR/shield/UpdateCheck.swift" \
    "$DIR/shield/ShieldApp.swift" "$DIR/shield/main.swift" \
    -o "$BUILD/shield-$arch"
done
lipo -create -output "$CONTENTS/MacOS/Shield" "$BUILD/shield-arm64" "$BUILD/shield-x86_64"
rm -f "$BUILD/shield-arm64" "$BUILD/shield-x86_64"
lipo -info "$CONTENTS/MacOS/Shield" | sed 's/^/  /'

echo "→ 编译看门狗（独立进程）"
# 只依赖 Foundation + Darwin：父进程没了它还得活着，不能和界面绑在一起。
for arch in arm64 x86_64; do
  swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. -target "$arch-apple-macosx11.0" \
    "$DIR/shield/watchdog/main.swift" -o "$BUILD/watchdog-$arch"
done
lipo -create -output "$CONTENTS/MacOS/ShieldWatchdog" \
  "$BUILD/watchdog-arm64" "$BUILD/watchdog-x86_64"
rm -f "$BUILD/watchdog-arm64" "$BUILD/watchdog-x86_64"
chmod +x "$CONTENTS/MacOS/ShieldWatchdog"
lipo -info "$CONTENTS/MacOS/ShieldWatchdog" | sed 's/^/  /'

echo "→ 拷贝面板"
mkdir -p "$CONTENTS/Resources/web"
cp "$DIR/shield/web/shield.html" "$DIR/shield/web/shield.css" "$DIR/shield/web/shield.js" \
   "$CONTENTS/Resources/web/"

cp "$DIR/tools/Shield-Info.plist" "$CONTENTS/Info.plist"

# ad-hoc 签名：不签名的话 macOS 会因为「已损坏」直接拒绝启动，
# 这个签名只保证本机能跑，不代表任何身份
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

echo
echo "✓ 构建完成：$APP"
du -sh "$APP" | sed 's/^/  /'
