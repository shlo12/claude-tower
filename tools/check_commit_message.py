#!/usr/bin/env python3
"""Keep project commit messages free of automatic generation/credit footers."""
import re
import sys
from pathlib import Path

def forbidden(message):
    return bool(re.search(r'(?im)^\s*(?:generated\s+(?:by|with)\b|co-authored' + r'-by\s*:)', message))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit(2)
    if forbidden(Path(sys.argv[1]).read_text(encoding='utf-8')):
        print('Commit rejected: remove automatic generation and shared-credit footers.')
        raise SystemExit(1)
