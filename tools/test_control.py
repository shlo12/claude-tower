#!/usr/bin/env python3
"""隔离验证统一守护状态、维修闸门和有限指令回执。"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import control, shield


class ControlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.patches = [patch.object(shield, 'STATE_DIR', self.dir),
                        patch.object(shield, 'STATE_FILE', self.dir / 'shield.json'),
                        patch.object(shield, 'running', return_value=True),
                        patch.object(shield, 'launch_agent_state', return_value='none'),
                        patch.object(control.sys, 'platform', 'darwin'),
                        patch.object(control.compat, 'claude_processes', return_value=[])]
        for p in self.patches: p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patches)])
        self.addCleanup(self.tmp.cleanup)

    def write(self, state='active', age=0):
        shield.STATE_FILE.write_text(json.dumps({'enabled': True, 'level': 2,
            'live': {'at': time.time()-age, 'sessionState': state}}))

    def test_authority_and_freshness(self):
        self.write()
        self.assertEqual(control.status()['state'], 'active')
        self.assertTrue(control.maintenance_blocked())
        self.write(age=50)
        self.assertEqual(control.status()['state'], 'unknown')
        self.assertTrue(control.maintenance_blocked())
        with patch.object(shield, 'running', return_value=False):
            self.assertFalse(control.status()['fresh'])
            self.assertEqual(control.status()['state'], 'unknown')

    def test_maintenance_waits_for_process_exit(self):
        self.write('waiting')
        self.assertFalse(control.maintenance_blocked())
        with patch.object(control.compat, 'claude_processes', return_value=[{'pid': 42}]):
            self.assertTrue(control.maintenance_blocked())

    def test_unsupported_never_reports_monitoring(self):
        self.write()
        with patch.object(control.sys, 'platform', 'win32'):
            self.assertFalse(control.status()['supported'])
            self.assertFalse(control.status()['fresh'])
            with self.assertRaises(RuntimeError): control.send('session-start')

    def test_maintenance_lease_and_session_lock(self):
        self.write('active')
        with self.assertRaises(RuntimeError): control.begin_maintenance()
        self.write('waiting')
        fd = control.begin_maintenance()
        try:
            with self.assertRaises(OSError): control.begin_maintenance()
        finally: os.close(fd)
        next_fd = control.begin_maintenance()
        os.close(next_fd)

    @unittest.skipUnless(sys.platform == 'darwin', '原生文件通道仅 macOS')
    def test_native_command_validation(self):
        root = Path(__file__).resolve().parent.parent
        src = (root / 'shield/ShieldApp.swift').read_text()
        method = src.split('    func consumeCommand() {', 1)[1].split('    func handleAction', 1)[0]
        harness = r'''
import Foundation
import Darwin
enum Store { static var dir = URL(fileURLWithPath: CommandLine.arguments[1]) }
final class Monitor {
 var actions: [String] = []
 func handleAction(_ b: [String: Any]) { actions.append(b["action"] as! String) }
 func consumeCommand() {
''' + method + r'''
}
let monitor = Monitor()
let request = Store.dir.appendingPathComponent("shield-command.json")
func emit(_ action: String, age: Double = 0, mode: Int = 0o600) {
 let row: [String: Any] = ["id": UUID().uuidString, "action": action, "at": Date().timeIntervalSince1970 - age]
 try! JSONSerialization.data(withJSONObject: row).write(to: request)
 try! FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: request.path)
 monitor.consumeCommand()
}
emit("now", age: 60); precondition(monitor.actions.isEmpty)
emit("now", mode: 0o644); precondition(monitor.actions.isEmpty)
emit("arbitrary-command"); precondition(monitor.actions.isEmpty)
emit("now"); precondition(monitor.actions == ["now"])
monitor.consumeCommand(); precondition(monitor.actions.count == 1)
emit("strict"); precondition(monitor.actions == ["now", "level"])
let result = Store.dir.appendingPathComponent("shield-command-result.json")
let mode = (try! FileManager.default.attributesOfItem(atPath: result.path))[.posixPermissions] as! NSNumber
precondition(mode.intValue == 0o600)
'''
        main = self.dir / 'main.swift'; main.write_text(harness)
        binary = self.dir / 'validation'
        subprocess.run(['swiftc', str(main), '-o', str(binary)], check=True, capture_output=True)
        subprocess.run([str(binary), str(self.dir)], check=True, capture_output=True)

    def test_limited_commands(self):
        with self.assertRaises(ValueError): control.send('exec /bin/sh')
        (self.dir / 'shield-command.json').write_text('{}')
        with self.assertRaises(RuntimeError): control.send('now')

    def test_private_atomic_request_and_matching_ack(self):
        seen = []
        def worker():
            request = self.dir / 'shield-command.json'
            for _ in range(100):
                if request.exists():
                    row = json.loads(request.read_text())
                    seen.append((row, request.stat().st_mode & 0o777))
                    (self.dir / 'shield-command-result.json').write_text(json.dumps({'id': row['id'], 'ok': True}))
                    request.unlink()
                    return
                time.sleep(.01)
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(control.send('session-end')['accepted'])
        thread.join(2)
        self.assertEqual(seen[0][1], 0o600)
        self.assertEqual(set(seen[0][0]), {'id', 'at', 'action'})


if __name__ == '__main__': unittest.main()
