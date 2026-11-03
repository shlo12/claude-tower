#!/usr/bin/env python3
"""定位服务开关：读缓存、判过期、授权失败不当作「关着」。

真实读取要管理员授权，测试里不跑 `osascript`——把 `subprocess.run` 换成
假返回，固定的是「拿到什么输出算开、算关、算读不出来」，以及缓存过期后
不能再拿旧值下结论。

    python3 tools/test_location.py
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import location  # noqa: E402


class Fake:
    def __init__(self, code=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = code, out, err


class ParseTests(unittest.TestCase):
    def test_on_values(self):
        for text in ("1", "true", "YES", " 1\n"):
            self.assertIs(location._parse(text), True, text)

    def test_off_values(self):
        for text in ("0", "false", "No", " 0\n"):
            self.assertIs(location._parse(text), False, text)

    def test_unknown_values_are_not_guessed(self):
        # UNKNOWN / MISSING / 空：读不出来就说读不出来，不能当成「关着」
        for text in ("UNKNOWN", "MISSING", "", None, "2"):
            self.assertIsNone(location._parse(text), text)


class ReadTests(unittest.TestCase):
    def run_read(self, **kwargs):
        with patch.object(location.compat, "IS_MAC", True), \
                patch.object(location.subprocess, "run", lambda *a, **k: Fake(**kwargs)):
            return location.read()

    def test_enabled(self):
        out = self.run_read(out="1\n")
        self.assertTrue(out["checked"])
        self.assertIs(out["enabled"], True)

    def test_disabled(self):
        out = self.run_read(out="0\n")
        self.assertTrue(out["checked"])
        self.assertIs(out["enabled"], False)

    def test_cancel_is_reported_not_guessed(self):
        out = self.run_read(code=1, err="execution error: User canceled. (-128)")
        self.assertFalse(out["checked"])
        self.assertIsNone(out["enabled"])
        self.assertIn("取消", out["error"])

    def test_other_failure_keeps_the_message(self):
        out = self.run_read(code=1, err="some other error")
        self.assertFalse(out["checked"])
        self.assertIn("some other error", out["error"])

    def test_missing_plist(self):
        out = self.run_read(out="MISSING\n")
        self.assertFalse(out["checked"])
        self.assertIn("没找到", out["error"])

    def test_unrecognised_output(self):
        out = self.run_read(out="banana\n")
        self.assertFalse(out["checked"])
        self.assertIn("无法识别", out["error"])

    def test_non_mac_is_unsupported(self):
        with patch.object(location.compat, "IS_MAC", False):
            out = location.read()
        self.assertFalse(out["checked"])
        self.assertIn("macOS", out["error"])


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.state = self.tmp / "location.json"
        patcher = patch.object(location, "STATE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, enabled, age=0):
        self.state.write_text(json.dumps({
            "version": 1, "at": time.time() - age, "enabled": enabled,
        }), encoding="utf-8")

    def test_no_cache(self):
        out = location.status()
        self.assertFalse(out["checked"])
        self.assertIsNone(out["enabled"])
        self.assertFalse(out["stale"])
        self.assertEqual(out["age"], None)

    def test_fresh_cache(self):
        self.write(True)
        out = location.status()
        self.assertTrue(out["checked"])
        self.assertIs(out["enabled"], True)

    def test_stale_cache_does_not_answer(self):
        self.write(True, age=location.STALE + 60)
        out = location.status()
        self.assertTrue(out["stale"])
        self.assertFalse(out["checked"])
        # 过期之后不能再回「开着」或「关着」，两者都是编的
        self.assertIsNone(out["enabled"])

    def test_broken_cache_is_ignored(self):
        self.state.write_text("{ 不是 json", encoding="utf-8")
        out = location.status()
        self.assertFalse(out["checked"])
        self.assertIsNone(out["enabled"])

    def test_wrong_version_is_ignored(self):
        self.state.write_text(json.dumps({"version": 9, "enabled": True}),
                              encoding="utf-8")
        self.assertFalse(location.status()["checked"])


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.state = self.tmp / "location.json"
        patcher = patch.object(location, "STATE", self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def refresh(self, **kwargs):
        with patch.object(location.compat, "IS_MAC", True), \
                patch.object(location.subprocess, "run", lambda *a, **k: Fake(**kwargs)):
            return location.refresh()

    def test_success_writes_a_private_record(self):
        out = self.refresh(out="1\n")
        self.assertTrue(out["checked"])
        self.assertIs(out["enabled"], True)
        self.assertIn("开着", out["message"])
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o600)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertIs(saved["enabled"], True)

    def test_failure_leaves_no_record(self):
        out = self.refresh(code=1, err="User canceled. (-128)")
        self.assertIn("error", out)
        self.assertIn("取消", out["error"])
        # 没读到就不能留记录，否则下次扫描会把「没读到」当成「关着」
        self.assertFalse(self.state.exists())

    def test_second_refresh_overwrites(self):
        self.refresh(out="1\n")
        out = self.refresh(out="0\n")
        self.assertIs(out["enabled"], False)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertIs(saved["enabled"], False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
