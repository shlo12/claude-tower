#!/usr/bin/env python3
"""录制真实塔顶过场（隔离演示数据，不扫描或修改用户环境）。

python3 tools/record-demo.py → build/preview/finisher.mp4
打包与产品运行不依赖 Playwright / Node / ffmpeg；它们仅用于开发录屏。
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = Path(os.environ['CCLEAN_DEV_RUNTIME']) if os.environ.get('CCLEAN_DEV_RUNTIME') else None


def main():
    node = os.environ.get('CCLEAN_NODE') or shutil.which('node') or (str(RUNTIME / 'node/bin/node') if RUNTIME else '')
    ffmpeg = os.environ.get('CCLEAN_FFMPEG') or shutil.which('ffmpeg') or '/opt/homebrew/bin/ffmpeg'
    env = dict(os.environ)
    modules = str(RUNTIME / 'node/node_modules') if RUNTIME else ''
    env['NODE_PATH'] = os.pathsep.join(filter(None, [env.get('NODE_PATH'), modules]))
    env['CCLEAN_FFMPEG'] = ffmpeg
    if not node or not Path(node).exists() or not Path(ffmpeg).exists():
        print('录屏需要开发机提供 Node 与 ffmpeg；也可通过 CCLEAN_NODE / CCLEAN_FFMPEG 指定。')
        return 1
    return subprocess.call([node, str(ROOT / 'tools/record-demo.cjs')], cwd=ROOT, env=env)


if __name__ == '__main__':
    sys.exit(main())
