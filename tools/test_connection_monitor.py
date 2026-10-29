#!/usr/bin/env python3
"""编译真实 Swift 判据；不连接代理、不终止真实进程。"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
HARNESS = r'''
import Foundation
func check(_ ok: Bool, _ name: String) { if !ok { fatalError(name) }; print("PASS " + name) }
typealias M = ConnectionMonitor
let ps = M.processes("10 1 /Applications/Claude.app/Contents/MacOS/Claude\n11 10 /bin/tool\n12 1 /Applications/Claude Shield.app/Contents/MacOS/Shield\n13 11 /bin/child")
check(M.claudePIDs(ps) == Set([10, 11, 13]), "process tree excludes shield")
for app in ["Clash Verge", "FlClash", "Shadowrocket", "Surge"] {
 check(M.supportedClient("/Applications/" + app + ".app/Contents/MacOS/core"), "client " + app)
}
check(!M.supportedClient("/Applications/Other.app/Contents/MacOS/core"), "unrelated listener")
check(M.endpoint("[::1]:7890")?.host == "::1", "IPv6 endpoint")
check(M.endpoint("bad:99999") == nil, "invalid endpoint")
let text = "p10\nf3\nPTCP\nn127.0.0.1:50000->127.0.0.1:7890\nTST=ESTABLISHED\np20\nf4\nPTCP\nn127.0.0.1:7890\nTST=LISTEN\n"
let rows = M.sockets(text)
check(rows.count == 2 && rows[1].state == "LISTEN", "lsof record boundaries")
let local = M.classify(rows, claude: [10], clients: [20], routes: [:])
check(local.state == "local" && local.localProxy == 1, "owned proxy listener")
let untrusted = M.classify(rows, claude: [10], clients: [21], routes: [:])
check(untrusted.state == "unknown", "untrusted loopback never safe")
let remote = M.SocketInfo(pid: 10, proto: "TCP", name: "10.0.0.2:50000->8.8.8.8:443", state: "ESTABLISHED")
let direct = M.classify([remote], claude: [10], clients: [], routes: ["8.8.8.8":"en0"])
check(direct.direct == 1 && direct.state == "direct", "physical route bypass")
let tun = M.classify([remote], claude: [10], clients: [], routes: ["8.8.8.8":"utun4"])
check(tun.state == "unknown" && tun.direct == 0, "TUN route is not proxy proof")
let ambiguous = M.classify([remote], claude: [10], clients: [], routes: ["8.8.8.8":"en0"], tunActive: true)
check(ambiguous.direct == 0 && ambiguous.state == "unknown", "active tunnel avoids transparent proxy false kill")
let missing = M.classify([remote], claude: [10], clients: [], routes: [:])
check(missing.state == "unknown", "route failure never safe")
let udp = M.SocketInfo(pid: 10, proto: "UDP", name: "*:443", state: "")
check(M.classify([udp], claude: [10], clients: [], routes: [:]).unknown == 1, "unconnected UDP unknown")
let ipv6 = M.SocketInfo(pid: 10, proto: "UDP", name: "[::]:5000->[2606:4700:4700::1111]:443", state: "")
check(M.classify([ipv6], claude: [10], clients: [], routes: ["2606:4700:4700::1111":"en0"]).direct == 1, "IPv6 public bypass")
check(!M.isPublic("192.168.1.1") && !M.isPublic("198.18.0.1") && !M.isPublic("fe80::1"), "private and fake IP unknown")
var snap = Snapshot(); snap.claudeRunning = true; snap.sysProxy = true; snap.connections = direct
check(snap.verdict == .danger && !snap.environmentReady, "system proxy switch cannot hide direct socket")
snap.connections = missing
check(snap.verdict != .danger, "unknown alone never kills")
check(M.classify([], claude: [10], clients: [], routes: [:]).state == "unknown", "empty snapshot not safe")
let inbound = M.SocketInfo(pid: 10, proto: "TCP", name: "*:50000", state: "LISTEN")
check(M.classify([remote, inbound], claude: [10], clients: [], routes: ["8.8.8.8":"en0"]).direct == 0, "accepted inbound connection not direct bypass")
'''

class ConnectionMonitorTests(unittest.TestCase):
    def test_real_swift_classification(self):
        with tempfile.TemporaryDirectory(prefix='shield-connections-') as folder:
            d = Path(folder)
            (d / 'main.swift').write_text(HARNESS)
            env = dict(os.environ, CLANG_MODULE_CACHE_PATH='/tmp/ccclean-clang-cache')
            result = subprocess.run(['/usr/bin/swiftc', str(ROOT / 'shield/Probe.swift'),
                                     str(d / 'main.swift'), '-o', str(d / 'check')],
                                    capture_output=True, text=True, env=env, timeout=180)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(d / 'check')], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.count('PASS '), 22)

if __name__ == '__main__':
    unittest.main()
