#!/bin/sh
# 繁体中文版构建管线：把整棵源码复制到 build/zhhant-src/，
# 简体转繁体 + 去掉产品名里的 Claude（CC Tower→Tower、CC Shield→Shield），
# 然后在暂存树里跑 build-app.sh，产出 Tower.app（内嵌 Shield.app）。
#
# 注意：只改产品自身的名字，不碰「桌面端 Claude.app」这类指代真身的字符串——
# 替换用的都是带空格的完整产品名。
set -eu

DIR="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="$DIR/build/vm-zhhant"
SRC="$STAGE/src"

echo "→ 暂存源码到 $SRC"
rm -rf "$STAGE"
mkdir -p "$SRC"
rsync -a \
  --exclude '.git' --exclude 'build' --exclude 'dist' --exclude '*.app' \
  --exclude '__pycache__' --exclude '.workbuddy-ai' \
  "$DIR/" "$SRC/"

# 复用 Python 运行时缓存，省一次下载
if [ -d "$DIR/build/python-src" ]; then
  mkdir -p "$SRC/build"
  cp -R "$DIR/build/python-src" "$SRC/build/"
fi

# 明确标记本变体；普通构建没有此标记，保留原准入规则。
printf '%s\n' '{"version":1,"network":"managed-mihomo"}' > "$SRC/vm-profile.json"

echo "→ 编译简繁转换器"
swiftc -O "$DIR/tools/hans2hant.swift" -o "$STAGE/hans2hant"

echo "→ 文件内容简体→繁体"
find "$SRC" -type f \( \
    -name '*.py' -o -name '*.swift' -o -name '*.js' -o -name '*.html' \
    -o -name '*.css' -o -name '*.txt' -o -name '*.plist' -o -name '*.sh' \
    -o -name '*.md' -o -name '*.json' -o -name '*.bat' -o -name '*.command' \
    -o -name '*.jsonl' \
  \) -print0 | xargs -0 "$STAGE/hans2hant"

echo "→ 文件名/目录名简体→繁体"
"$STAGE/hans2hant" --names "$SRC"

echo "→ 产品名去掉 Claude"
find "$SRC" -type f \( \
    -name '*.py' -o -name '*.swift' -o -name '*.js' -o -name '*.html' \
    -o -name '*.css' -o -name '*.txt' -o -name '*.plist' -o -name '*.sh' \
    -o -name '*.md' -o -name '*.json' -o -name '*.bat' -o -name '*.command' \
  \) -print0 | xargs -0 perl -CSD -pi -e '
    s/CC Tower\.app/Tower.app/g;
    s/CC Shield\.app/Shield.app/g;
    s/CC Tower/Tower/g;
    s/CC Shield/Shield/g;
    s/CCTower/Tower/g;
    s/CCShield/Shield/g;
    s/cc-tower/tower/g;
  '

# 文件名里的产品名也要改（如 CC Tower.bat → Tower.bat）
find "$SRC" -depth \( -name '*Claude*' -o -name '*CC Tower*' -o -name '*CC Shield*' \) | while IFS= read -r p; do
  new="$(basename "$p" | sed 's/CC Tower/Tower/g; s/CC Shield/Shield/g; s/Claude//g')"
  [ "$new" = "$(basename "$p")" ] || mv "$p" "$(dirname "$p")/$new"
done

echo "→ 验证：暂存树里不该再出现产品名"
if grep -rn "CC Tower\|CC Shield\|CCTower\|CCShield" "$SRC" --include='*.py' --include='*.swift' --include='*.js' --include='*.html' --include='*.plist' --include='*.sh' 2>/dev/null; then
  echo "✗ 还有漏网的产品名"
  exit 1
fi

echo "→ 暂存树自检（check.py）"
(cd "$SRC" && python3 tools/check.py) || { echo "✗ 自检失败"; exit 1; }

echo "→ 构建 Tower.app"
"$SRC/tools/build-app.sh"

mv "$SRC/Tower.app" "$STAGE/Tower.app"

# 归档到 dist/vm/：这是虚拟机专用变体（繁中+去 Claude 命名），和宿主版分开放，
# 免得以后从 build/ 或 dist/ 根目录里拿混。
DIST_VM="$DIR/dist/vm"
mkdir -p "$DIST_VM"
rm -rf "$DIST_VM/Tower.app"
cp -R "$STAGE/Tower.app" "$DIST_VM/Tower.app"
VER="$(sed -n 's/^VERSION = "\(.*\)"$/\1/p' "$SRC/app.py" | head -n 1)"
tar -czf "$DIST_VM/Tower-${VER:-unknown}-vm-zhhant.tar.gz" -C "$STAGE" Tower.app

echo "✓ 产出：$STAGE/Tower.app"
echo "✓ 归档：$DIST_VM/Tower.app + Tower-${VER:-unknown}-vm-zhhant.tar.gz"
