#!/bin/sh
# 打一个可自动更新的 Release：一个 .app 包、更新清单和发布命令。
#
# 用法：
#   tools/make-release.sh                 # 版本说明取 README 里的最新一节？没有就留空
#   tools/make-release.sh notes.md        # 把这份 Markdown 写进 Release 和清单
#
# 产物在 dist/release-vX.Y.Z/：
#   ClaudeTower-X.Y.Z.zip     塔（里面嵌着 Claude Shield.app）
#   update-manifest.json      体积、SHA256、最低系统版本、内置哨兵版本
#
# 两个文件必须一起上传到同一个 GitHub Release，少一个塔就拒绝更新。
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
NOTES_FILE="${1:-}"
python3 "$DIR/tools/check_release.py" --source --history

VERSION="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$DIR/app.py" | head -n 1)"
SHIELD_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
  "$DIR/tools/Shield-Info.plist")"
if [ -z "$VERSION" ] || [ -z "$SHIELD_VERSION" ]; then
  echo "✗ 读不到版本号（app.py / Shield-Info.plist）" >&2
  exit 1
fi

echo "→ 构建塔 $VERSION（内含哨兵 $SHIELD_VERSION）"
"$DIR/tools/build-app.sh"

OUT="$DIR/dist/release-v$VERSION"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "→ 打包（保留中文文件名标记与可执行位）"
python3 "$DIR/tools/pack_zip.py" "$DIR/Claude Tower.app" \
  "$OUT/ClaudeTower-$VERSION.zip"
python3 "$DIR/tools/check_release.py" "$OUT/ClaudeTower-$VERSION.zip"

echo "→ 生成更新清单"
python3 - "$OUT" "$VERSION" "$SHIELD_VERSION" "${NOTES_FILE:-}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
version, shield_version = sys.argv[2], sys.argv[3]
notes_file = sys.argv[4]
notes = ""
if notes_file:
    notes = Path(notes_file).read_text(encoding="utf-8")[:4000]

assets = {}
name = f"ClaudeTower-{version}.zip"
data = (out / name).read_bytes()
assets["tower"] = {
    "name": name,
    "bytes": len(data),
    "sha256": hashlib.sha256(data).hexdigest(),
}

manifest = {
    "schema": 1,
    "version": version,
    "shieldVersion": shield_version,
    "minMacOS": "11.0",
    "notes": notes,
    "assets": assets,
}
(out / "update-manifest.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8")
print(f"  {assets['tower']['name']}  {assets['tower']['bytes'] / 1048576:.1f} MB")
PY
python3 "$DIR/tools/pack-source.py" "$OUT/ClaudeTower-$VERSION-source.zip"
python3 "$DIR/tools/check_release.py" --source --history "$OUT/ClaudeTower-$VERSION.zip" "$OUT/ClaudeTower-$VERSION-source.zip"
python3 - "$OUT" <<'PY'
import hashlib, sys
from pathlib import Path
out = Path(sys.argv[1])
files = sorted(p for p in out.iterdir() if p.is_file() and p.name != 'SHA256SUMS-release.txt')
(out / 'SHA256SUMS-release.txt').write_text('\n'.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name for p in files) + '\n')
PY

echo
echo "✓ 产物：$OUT"
ls -lh "$OUT" | sed 's/^/  /'
echo
echo "下一步（需要已登录 gh）："
echo "  gh release create \"v$VERSION\" \\"
echo "    \"$OUT/ClaudeTower-$VERSION.zip\" \\"
echo "    \"$OUT/update-manifest.json\" \\"
echo "    --title \"v$VERSION\" --notes-file <说明.md>"
echo
echo "发布前先在塔的「隐私设置 → 自动更新」里填 owner/repo；"
echo "清单里的体积和 SHA256 与 zip 对不上时，塔会拒绝下载。"
