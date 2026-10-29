#!/bin/sh
# CCclean 启动器
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"

PY="${CCLEAN_PYTHON:-}"
if [ -z "$PY" ]; then
  for candidate in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      PY="$candidate"
      break
    fi
  done
fi

if [ -z "$PY" ]; then
  echo "找不到 python3，请先安装 Python 3.10+（brew install python）" >&2
  exit 1
fi

exec "$PY" "$DIR/app.py" "$@"
