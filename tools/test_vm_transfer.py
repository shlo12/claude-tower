#!/usr/bin/env python3
"""Exercise the actual receiver with isolated streams and private temporary homes."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vm_receiver", ROOT / "tools/vm-transfer/receiver.py")
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)
audit_spec = importlib.util.spec_from_file_location("vm_audit", ROOT / "tools/vm-transfer/audit.py")
audit = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit)


def rec(data):
    return json.dumps(data).encode() + b"\n"


def wire(files, commit=True, bad_hash=False):
    output = rec({"version": 1, "files": len(files)})
    for name, data in files:
        output += rec({"name": name, "size": len(data)})
        output += base64.encodebytes(data)
        output += rec({"end": True, "sha256": "bad" if bad_hash else hashlib.sha256(data).hexdigest()})
    if commit:
        output += rec({"commit": True})
    return io.BytesIO(output)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def batches(self):
        p = self.home / "Downloads/VM-Inbox"
        return list(p.iterdir()) if p.exists() else []

    def test_binary_unicode_empty_and_file_modes(self):
        files = [("測試 ' $() `; .bin", bytes(range(256)) * 4000), ("empty.txt", b"")]
        result = receiver.receive(wire(files), self.home)
        self.assertTrue(result["ok"])
        self.assertEqual(result["bytes"], 1024000)
        batch = self.batches()[0]
        self.assertEqual(stat.S_IMODE(batch.stat().st_mode), 0o700)
        for name, data in files:
            self.assertEqual((batch / name).read_bytes(), data)
            self.assertEqual(stat.S_IMODE((batch / name).stat().st_mode), 0o600)

    def test_no_overwrite_between_batches(self):
        receiver.receive(wire([("a.txt", b"one")]), self.home)
        receiver.receive(wire([("a.txt", b"two")]), self.home)
        self.assertEqual(sorted((b / "a.txt").read_bytes() for b in self.batches()), [b"one", b"two"])

    def test_bad_hash_removes_entire_batch(self):
        with self.assertRaises(receiver.TransferError):
            receiver.receive(wire([("a", b"secret")], bad_hash=True), self.home)
        self.assertEqual(self.batches(), [])

    def test_eof_before_commit_removes_entire_batch(self):
        with self.assertRaises(receiver.TransferError):
            receiver.receive(wire([("a", b"data")], commit=False), self.home)
        self.assertEqual(self.batches(), [])

    def test_explicit_cancel_removes_entire_batch(self):
        data = (rec({"version": 1, "files": 1}) + rec({"name": "a", "size": 99})
                + base64.encodebytes(b"partial") + rec({"abort": True}))
        with self.assertRaises(receiver.TransferError):
            receiver.receive(io.BytesIO(data), self.home)
        self.assertEqual(self.batches(), [])

    def test_idle_timeout_cleans_up_even_when_stdin_stays_open(self):
        code = """
import importlib.util,signal,sys
spec=importlib.util.spec_from_file_location('r',sys.argv[1]);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
def timeout(*args):raise r.TransferError('interrupted')
signal.signal(signal.SIGALRM,timeout);r.READ_TIMEOUT=1
try:r.receive(sys.stdin.buffer,sys.argv[2])
except r.TransferError:print('idle-cleaned',flush=True)
"""
        p = subprocess.Popen([sys.executable, "-c", code, str(ROOT / "tools/vm-transfer/receiver.py"), str(self.home)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            p.stdin.write(rec({"version": 1, "files": 1}) + rec({"name": "a", "size": 10}) + b"YQ==\n")
            p.stdin.flush()  # Keep open: reproduces the Parallels missing-EOF case.
            self.assertEqual(p.wait(timeout=5), 0)
            self.assertEqual(p.stdout.read().strip(), b"idle-cleaned")
            self.assertEqual(self.batches(), [])

        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            p.stdin.close()
            p.stdout.close()
            p.stderr.close()

    def test_traversal_duplicates_and_control_characters_rejected(self):
        for files in [[("../outside", b"x")], [("/tmp/outside", b"x")], [("a\\b", b"x")],
                      [("a\nb", b"x")], [("a", b"x"), ("a", b"y")]]:
            with self.subTest(files=files):
                with self.assertRaises(receiver.TransferError):
                    receiver.receive(wire(files), self.home)
                self.assertEqual(self.batches(), [])

    def test_symlink_inbox_and_downloads_rejected(self):
        (self.home / "Downloads").mkdir()
        outside = self.home / "outside"
        outside.mkdir()
        (self.home / "Downloads/VM-Inbox").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(receiver.TransferError):
            receiver.receive(wire([("a", b"data")]), self.home)
        self.assertEqual(list(outside.iterdir()), [])
        (self.home / "Downloads/VM-Inbox").unlink()
        (self.home / "Downloads").rmdir()
        (self.home / "Downloads").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(receiver.TransferError):
            receiver.receive(wire([("a", b"data")]), self.home)

    def test_size_and_corrupt_stream_rejected(self):
        for stream in [rec({"version": 1, "files": 1}) + rec({"name": "a", "size": receiver.MAX_FILE + 1}),
                       rec({"version": 1, "files": 1}) + rec({"name": "a", "size": 0}) + b"YQ==\n",
                       rec({"version": 1, "files": 1}) + rec({"name": "a", "size": 1}) + b"?!\n"]:
            with self.assertRaises(receiver.TransferError):
                receiver.receive(io.BytesIO(stream), self.home)
            self.assertEqual(self.batches(), [])


class AuditTests(unittest.TestCase):
    def test_tracks_each_tagged_process_without_matching_embedded_text(self):
        a, b = "a" * 32, "b" * 32
        text = (f"101 S /usr/bin/python3 -c encoded --cc-vm-transfer-session={a}\n"
                f"102 S /usr/bin/python3 -c encoded --cc-vm-transfer-session={b}\n"
                "103 S /usr/bin/python3 -c encoded all\n"
                f"104 S /usr/bin/python3 -c prefix--cc-vm-transfer-session={a}\n"
                f"105 S /usr/bin/python3 -c encoded --cc-vm-transfer-session={a}invalid\n")
        self.assertEqual(audit.sessions(text), {101: a, 102: b})

    def test_ignores_zombies_and_auditor_itself(self):
        token = "a" * 32
        text = (f"101 Z /usr/bin/python3 --cc-vm-transfer-session={token}\n"
                f"102 S /usr/bin/python3 --cc-vm-transfer-session={token}\n")
        self.assertEqual(audit.sessions(text, exclude=102), {})

    def test_invalid_or_absent_marker_never_becomes_receiver(self):
        self.assertEqual(audit.sessions("bad row\n123 S python3\n124 S other --session=all\n"), {})


@unittest.skipUnless(sys.platform == "darwin", "native AppKit drop handling is macOS-only")
class NativeDropTests(unittest.TestCase):
    def test_actual_native_drop_entry_and_busy_gates(self):
        source = (ROOT / "tools/vm-transfer/VMTransfer.swift").read_text().split("\nsignal(SIGPIPE", 1)[0]
        harness = r'''
let application = NSApplication.shared
application.setActivationPolicy(.accessory)
func require(_ value: Bool, _ message: String) { if !value { fatalError(message) } }
let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: root) }
let first = root.appendingPathComponent("中文檔案.txt"), second = root.appendingPathComponent("empty.bin")
try Data("safe test".utf8).write(to: first); try Data().write(to: second)
let pb = NSPasteboard.withUniqueName()
func files(_ urls: [URL]) { pb.clearContents(); require(pb.writeObjects(urls.map { $0 as NSURL }), "pasteboard write") }
let view = FileDropView(frame: NSRect(x:0,y:0,width:500,height:76))
var allowed = true, received: [[URL]] = [], rejections: [String] = []
view.canDrop = { allowed }; view.onFiles = { received.append($0) }; view.onRejected = { rejections.append($0) }
files([first,second])
require(view.accept(pb), "multiple Finder file URLs accepted")
require(received.count == 1 && received[0] == [first,second], "one drop invokes the shared callback once")
allowed = false
require(!view.accept(pb) && received.count == 1, "blocked state cannot dispatch a transfer")
allowed = true
files([root]); require(!view.accept(pb), "directory must be zipped first")
let link = root.appendingPathComponent("link")
try FileManager.default.createSymbolicLink(at: link, withDestinationURL: first)
files([link]); require(!view.accept(pb), "symlink must not be followed")
let remote = NSPasteboardItem(); remote.setString("https://example.com/file", forType: .fileURL)
pb.clearContents(); pb.writeObjects([remote]); require(!view.accept(pb), "web URL must not become a file")
files([first,first]); require(!view.accept(pb), "duplicate names must not dispatch")
pb.clearContents(); require(!view.accept(pb), "empty drop rejected")
require(received.count == 1 && rejections.count == 6, "invalid drops do not dispatch")
let delegate = AppDelegate()
delegate.vms = [VM(id: UUID().uuidString, name: "Test", running: true)]
delegate.vmPicker.addItem(withTitle: "Test")
require(!delegate.canReceiveFiles, "no closure proof must block drop")
delegate.lastClosure = ClosureCheck(host: 0, guest: 0)
require(delegate.canReceiveFiles, "verified idle target permits drop")
delegate.busy = true; require(!delegate.canReceiveFiles, "busy drop blocked"); delegate.busy = false
delegate.checking = true; require(!delegate.canReceiveFiles, "audit-in-progress drop blocked"); delegate.checking = false
delegate.selectingFiles = true; require(!delegate.canReceiveFiles, "open picker blocks concurrent drop"); delegate.selectingFiles = false
delegate.lastClosure = ClosureCheck(host: 0, guest: nil)
require(!delegate.canReceiveFiles, "unknown guest state must block drop")
print("native drop checks passed")
'''
        with tempfile.TemporaryDirectory() as directory:
            main = Path(directory) / "main.swift"
            binary = Path(directory) / "drop-check"
            main.write_text(source + "\n" + harness)
            build = subprocess.run(["swiftc", str(main), "-o", str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("native drop checks passed", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
