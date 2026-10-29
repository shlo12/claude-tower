#!/usr/bin/env python3
"""导出白名单源码，不导出 Git 历史、工具记忆、构建缓存或本机运行时。"""
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from check_release import BAD_PARTS, ROOT

version = re.search(r'^VERSION = "([^"]+)"', (ROOT / 'app.py').read_text(), re.M)[1]
out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'dist' / f'ClaudeTower-{version}-source.zip'
out.parent.mkdir(parents=True, exist_ok=True)
files = []
for name in ('core', 'shield', 'web', 'tools', 'docs', '.github'):
    for p in (ROOT / name).rglob('*'):
        rel = p.relative_to(ROOT)
        if (p.is_file() and not BAD_PARTS.intersection(rel.parts) and 'cache' not in rel.parts
                and p.suffix not in ('.pyc', '.zip') and p.name != '.DS_Store'):
            if p.is_symlink():
                raise RuntimeError('拒绝导出符号链接')
            files.append(p)
for name in ('app.py', 'README.md', 'SECURITY.md', 'AUTHORS.md', 'THIRD_PARTY_NOTICES.md',
             'PUBLISHING.md', 'RELEASE_AUDIT.md', 'RELEASE_NOTES.md', '.gitignore', 'run.sh', 'Claude Tower.bat'):
    p = ROOT / name
    if p.is_file():
        files.append(p)
subprocess.run([sys.executable, str(ROOT / 'tools/check_release.py'), '--source', '--history'], check=True)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for p in sorted(files):
        z.write(p, f'ClaudeTower-{version}-source/{p.relative_to(ROOT).as_posix()}')
subprocess.run([sys.executable, str(ROOT / 'tools/check_release.py'), str(out)], check=True)
print(out)
