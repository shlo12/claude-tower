#!/usr/bin/env python3
"""Compile the real native home policy; use only temporary homes and dummy children."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(sys.platform == "darwin", "native macOS launch environment")
class UserEnvironmentTests(unittest.TestCase):
    def test_actual_policy_and_child_under_root_home(self):
        harness = r'''
import Foundation
import Darwin
func check(_ value: Bool, _ reason: String) { if !value { fatalError(reason) } }
let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
let account = root.appendingPathComponent("account"), isolated = root.appendingPathComponent("isolated")
try FileManager.default.createDirectory(at: account, withIntermediateDirectories: true)
try FileManager.default.createDirectory(at: isolated, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: root) }
for bad in ["/", "", "/tmp/../", "relative/home", root.appendingPathComponent("missing").path] {
 let result = UserEnvironment.resolve(["HOME":bad,"KEEP_ME":"value","CLAUDE_CONFIG_DIR":"/intentional/config"], accountHome: account.path)
 check(result["HOME"] == account.path, "bad inherited home must use account home")
 check(result["KEEP_ME"] == "value" && result["CLAUDE_CONFIG_DIR"] == "/intentional/config", "unrelated environment preserved")
}
let valid = UserEnvironment.resolve(["HOME":isolated.path], accountHome:account.path)
check(valid["HOME"] == isolated.path, "intentional writable home preserved")
let fixed = UserEnvironment.resolve(["HOME":"/","CFFIXED_USER_HOME":isolated.path], accountHome:account.path)
check(fixed["HOME"] == isolated.path && fixed["CFFIXED_USER_HOME"] == isolated.path, "isolated native and Python homes stay aligned")
let invalidFixed = UserEnvironment.resolve(["HOME":"/","CFFIXED_USER_HOME":"/"], accountHome:account.path)
check(invalidFixed["HOME"] == account.path && invalidFixed["CFFIXED_USER_HOME"] == account.path, "root native override repaired")
check(UserEnvironment.resolve([:], accountHome:account.path)["HOME"] == account.path, "missing HOME repaired")
let file = root.appendingPathComponent("file"); try Data().write(to:file)
check(UserEnvironment.resolve(["HOME":file.path], accountHome:account.path)["HOME"] == account.path, "a regular file is not a home")
UserEnvironment.normalizeCurrentProcess()
let actual = String(cString:getpwuid(getuid())!.pointee.pw_dir!)
check(String(cString:getenv("HOME")) == actual, "process entry repairs HOME=/ from account database")
let process = Process(), output = Pipe()
process.executableURL = URL(fileURLWithPath:"/bin/sh")
process.arguments = ["-c", "printf '%s' \"$HOME\""]
process.environment = UserEnvironment.child; process.standardOutput = output
try process.run(); process.waitUntilExit()
let child = String(data:output.fileHandleForReading.readDataToEndOfFile(),encoding:.utf8)
check(process.terminationStatus == 0 && child == actual, "real child receives account home")
print("home policy checks passed")
'''
        with tempfile.TemporaryDirectory() as directory:
            main = Path(directory) / "main.swift"
            binary = Path(directory) / "home-check"
            main.write_text(harness)
            build = subprocess.run(["swiftc", str(ROOT / "tools/UserEnvironment.swift"), str(main), "-o", str(binary)],
                                   capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            env = dict(os.environ, HOME="/")
            env.pop("CFFIXED_USER_HOME", None)
            run = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("home policy checks passed", run.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
