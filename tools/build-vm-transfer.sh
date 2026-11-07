#!/bin/sh
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$ROOT/build/vm-transfer"
APP="$ROOT/dist/vm/傳入虛擬機.app"
mkdir -p "$STAGE" "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -target arm64-apple-macos11.0 "$ROOT/tools/vm-transfer/VMTransfer.swift" -o "$STAGE/arm64"
swiftc -O -target x86_64-apple-macos11.0 "$ROOT/tools/vm-transfer/VMTransfer.swift" -o "$STAGE/x86_64"
lipo -create "$STAGE/arm64" "$STAGE/x86_64" -output "$APP/Contents/MacOS/VMTransfer"
cp "$ROOT/tools/vm-transfer/receiver.py" "$APP/Contents/Resources/receiver.py"
cp "$ROOT/tools/vm-transfer/audit.py" "$APP/Contents/Resources/audit.py"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>VMTransfer</string>
<key>CFBundleIdentifier</key><string>com.ccclean.vm-transfer</string>
<key>CFBundleName</key><string>傳入虛擬機</string>
<key>CFBundleDisplayName</key><string>傳入虛擬機</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.2.0</string>
<key>CFBundleVersion</key><string>3</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>LSMinimumSystemVersion</key><string>11.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSHumanReadableCopyright</key><string>Copyright © 2026 shlo</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
swift "$ROOT/tools/vm-transfer/icon.swift" "$STAGE"
iconutil -c icns "$STAGE/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
ditto -c -k --keepParent --norsrc --noextattr "$APP" "$ROOT/dist/vm/VM-Transfer-1.2.0-macos.zip"
echo "完成：$APP"
