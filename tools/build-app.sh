#!/bin/sh
# 构建 Claude Tower.app（原生 macOS 应用包）
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$DIR/build"
APP="$DIR/Claude Tower.app"
CONTENTS="$APP/Contents"

echo "→ 清理旧构建"
# 不直接 rm -rf 整个 .app（上千个文件）：先挪到 build/trash-<时间戳>-XXXX/，
# 构建成功后再由使用者或 clean-build.sh 清掉。构建中途失败时，
# 上一版还完整躺在那里，不会出现「旧的删了、新的没成」的空窗。
# 用 mktemp -d 生成目录名：两次构建落在同一秒时，同名目录会让 mv 把源目录
# 塞进目标目录里（ENOTEMPTY），这种错只在连续构建时出现，很难查。
if [ -e "$APP" ] || [ -e "$BUILD/AppIcon.iconset" ]; then
  TRASH="$(mktemp -d "$BUILD/trash-$(date +%Y%m%d-%H%M%S)-XXXX")"
  if [ -e "$APP" ]; then
    mv "$APP" "$TRASH/"
    echo "  上一版已移到 $TRASH"
  fi
  [ -e "$BUILD/AppIcon.iconset" ] && mv "$BUILD/AppIcon.iconset" "$TRASH/"
fi
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources" "$BUILD"

echo "→ 生成图标"
swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. "$DIR/tools/make-icon.swift" -o "$BUILD/make-icon" >/dev/null 2>&1
"$BUILD/make-icon" "$BUILD/AppIcon.iconset" "$DIR/tools/app-icon.png" >/dev/null
iconutil -c icns "$BUILD/AppIcon.iconset" -o "$CONTENTS/Resources/AppIcon.icns"

echo "→ 编译宿主程序（arm64 + x86_64 通用）"
# 部署目标压到 11.0：能覆盖 Big Sur / Monterey。代码里用的都是 AppKit + WKWebView
# 的老接口，没有 macOS 13 才有的东西，没必要把门槛抬高——抬高了对方双击就一句
# 「此版本不能与此版本的 macOS 配合使用」，连个解释都没有。
swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. -target arm64-apple-macosx11.0 -framework Cocoa -framework WebKit \
    "$DIR/tools/CCcleanApp.swift" \
    -o "$BUILD/CCclean-arm64"
swiftc -O -file-prefix-map "$DIR"=. -debug-prefix-map "$DIR"=. -target x86_64-apple-macosx11.0 -framework Cocoa -framework WebKit \
    "$DIR/tools/CCcleanApp.swift" \
    -o "$BUILD/CCclean-x86_64"
lipo -create -output "$CONTENTS/MacOS/CCclean" "$BUILD/CCclean-arm64" "$BUILD/CCclean-x86_64"
rm -f "$BUILD/CCclean-arm64" "$BUILD/CCclean-x86_64"
lipo -info "$CONTENTS/MacOS/CCclean" | sed 's/^/  /'

echo "→ 拷贝应用资源"
mkdir -p "$CONTENTS/Resources/app"
cp "$DIR/app.py" "$CONTENTS/Resources/app/"
cp -R "$DIR/core" "$CONTENTS/Resources/app/"
cp -R "$DIR/web" "$CONTENTS/Resources/app/"
find "$CONTENTS/Resources/app" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

echo "→ 内置 Python 运行时（对方机器上可能一个 python3 都没有）"
for arch in arm64 x86_64; do
  "$DIR/tools/python-runtime.sh" "$arch" "$BUILD/py-$arch"
  mkdir -p "$CONTENTS/Resources/python"
  ditto "$BUILD/py-$arch" "$CONTENTS/Resources/python/$arch"
done

echo "→ 构建哨兵并嵌进 Resources（一个 .app、两个进程）"
# 哨兵是独立的菜单栏程序（LSUIElement），但必须跟着塔一起发出去：
# 单独放一个 .app 在 /Applications 里，用户会不知道要先开哪个、更新时
# 两个包还会各走各的。嵌在塔里，用户在 Finder 里看到的仍然只有一个图标。
"$DIR/tools/build-shield.sh" "$CONTENTS/Resources/Claude Shield.app"

cp "$DIR/tools/Info.plist" "$CONTENTS/Info.plist"

# 版本号只在 app.py 里维护，打包时同步进 Info.plist，避免两处对不上
VER="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$DIR/app.py" | head -n 1)"
if [ -n "${VER:-}" ]; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VER" "$CONTENTS/Info.plist" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VER" "$CONTENTS/Info.plist" >/dev/null 2>&1 || true
  echo "  版本：$VER"
fi

printf 'APPL????' > "$CONTENTS/PkgInfo"

echo "→ 签名（ad-hoc）"
# 包里现在有几百个 Mach-O（解释器 + 标准库的 .so），必须逐个签，
# 否则 arm64 上内核直接拒绝执行。--deep 会按正确顺序处理嵌套代码。
if ! codesign --force --deep --sign - "$APP" 2>/tmp/ccclean-sign.log; then
  echo "  ⚠ 签名失败："
  sed 's/^/    /' /tmp/ccclean-sign.log | head -10
fi
codesign --verify --deep --strict "$APP" 2>/dev/null \
  && echo "  签名校验：通过" || echo "  ⚠ 签名校验未通过（本机可能仍能跑，别人的机器会被拦）"

rm -f "$BUILD/make-icon"
echo "✓ 完成：$APP"
du -sh "$APP" | awk '{print "  体积：" $1}'
