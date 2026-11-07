#!/usr/bin/env python3
"""隔离运行真实 macOS 工具宿主 --service，不启动哨兵、不改系统设置。"""
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / 'CC Tower.app'


@unittest.skipUnless(sys.platform == 'darwin', 'macOS 原生宿主')
class ToolServiceTests(unittest.TestCase):
    def test_native_runtime_address_contract(self):
        src = (ROOT/'shield/ShieldApp.swift').read_text()
        # 只取 ToolRuntime 这一段：它不依赖 AppKit，能单独编译。按「下一个
        # final class」切，而不是写死 AppDelegate——中间随时可能插进新类
        # （ShieldPanel 就是这么插进来的），写死名字会让这条测试跟着编译失败。
        parser = 'enum ToolRuntime {' + src.split('enum ToolRuntime {',1)[1].split('\nfinal class ',1)[0]
        harness = r'''
import Foundation
''' + parser + r'''
func parse(_ url: String, pid: Int = 44, parent: Int = 7) -> Bool {
 let data = try! JSONSerialization.data(withJSONObject: ["url":url,"pid":pid,"parent":parent])
 return ToolRuntime.address(data,parent:7) != nil
}
precondition(parse("http://127.0.0.1:8787"))
precondition(parse("http://127.0.0.1:8787/"))
for bad in ["https://127.0.0.1:8787", "http://example.invalid:8787", "http://127.0.0.1:9000", "http://a:b@127.0.0.1:8787", "http://127.0.0.1:8787/other", "http://127.0.0.1:8787/?key=x"] {
 precondition(!parse(bad))
}
precondition(!parse("http://127.0.0.1:8787",pid:0))
precondition(!parse("http://127.0.0.1:8787",pid:Int.max))
precondition(!parse("http://127.0.0.1:8787",parent:8))
'''
        with tempfile.TemporaryDirectory(prefix='shield-address-') as directory:
            main=Path(directory)/'main.swift';main.write_text(harness)
            binary=Path(directory)/'check'
            subprocess.run(['swiftc',str(main),'-o',str(binary)],capture_output=True,check=True)
            subprocess.run([str(binary)],capture_output=True,check=True)

    def test_headless_engine_starts_in_isolated_home_and_keeps_signature(self):
        binary = APP / 'Contents/MacOS/CCclean'
        if not binary.exists(): self.skipTest('尚未构建本地应用')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with tempfile.TemporaryDirectory(prefix='shield-engine-') as directory:
            home = Path(directory)
            env = dict(os.environ, HOME=directory, CFFIXED_USER_HOME=directory, PYTHONDONTWRITEBYTECODE='1')
            process = subprocess.Popen([str(binary), '--service'], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                runtime = home / 'Library/Application Support/CCclean/runtime.json'
                deadline = time.monotonic() + 30
                metadata = None
                while time.monotonic() < deadline:
                    self.assertIsNone(process.poll(), '无窗口宿主提前退出')
                    if runtime.exists():
                        metadata = json.loads(runtime.read_text())
                        break
                    time.sleep(.1)
                self.assertIsNotNone(metadata, '隔离 HOME 中没有引擎运行记录')
                self.assertEqual(metadata['parent'], process.pid)
                base = metadata['url'].rstrip('/') + '/'
                html = opener.open(base + '?panel=1&tools=1', timeout=10).read().decode()
                token = re.search(r'<meta name="cc-token" content="([^"]+)"', html).group(1)
                req = urllib.request.Request(base + 'api/meta', headers={'X-CClean-Token': token})
                data = json.loads(opener.open(req, timeout=10).read())
                version = plistlib.loads((ROOT/'tools/Info.plist').read_bytes())['CFBundleShortVersionString']
                self.assertEqual(data['version'], version)
                self.assertEqual(data['home'], directory)
                self.assertIn('/panel.js', html)
                script = ('ObjC.import("AppKit");const a=$.NSRunningApplication.runningApplicationWithProcessIdentifier('
                          + str(process.pid) + ');a?Number(a.activationPolicy):-1;')
                policy = subprocess.run(['/usr/bin/osascript','-l','JavaScript','-e',script],capture_output=True,text=True,check=True)
                self.assertEqual(policy.stdout.strip(), '1', '工具宿主不应创建 Dock 入口')
                subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True,capture_output=True)
            finally:
                process.terminate()
                process.wait(timeout=10)
                # Python 子进程的父进程看门检查每两秒执行一次。
                time.sleep(2.2)


if __name__ == '__main__': unittest.main()
