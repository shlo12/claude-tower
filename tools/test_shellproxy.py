#!/usr/bin/env python3
"""终端代理变量：写进去、撤销掉、别碰别人的配置。

全部在临时目录里跑，不碰真实的 `~/.zshrc`。唯一被 mock 的是「测端口通不通」
——那一步会真的发网络请求，而这里要固定的是「写什么、删什么、什么情况下
拒绝写」。

    python3 tools/test_shellproxy.py
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import shellproxy as sp  # noqa: E402

ORIGINAL = """# 我原来的配置
export PATH="$HOME/bin:$PATH"
alias ll='ls -la'
"""


class Sandbox(unittest.TestCase):
    """每个用例一个临时 HOME：rc 文件、记录、备份都在里面。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.rc = self.tmp / ".zshrc"
        self.rc.write_text(ORIGINAL, encoding="utf-8")
        self.state = self.tmp / "shellproxy.json"
        self.backups = self.tmp / "backups"
        patches = [
            patch.object(sp, "STATE", self.state),
            patch.object(sp, "BACKUP_DIR", self.backups),
            patch.object(sp, "rc_path", lambda: (self.rc, "")),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def apply(self, port=7890):
        return sp.apply(port, prober=lambda p: {"ok": True, "ipMasked": "1.2.*.4"})


class BlockTests(unittest.TestCase):
    def test_block_carries_both_markers_and_exports(self):
        text = sp._block(7890)
        self.assertIn(sp.BLOCK0, text)
        self.assertIn(sp.BLOCK1, text)
        self.assertIn('export http_proxy="http://127.0.0.1:7890"', text)
        self.assertIn('export HTTPS_PROXY="$https_proxy"', text)
        # 本机回环必须排除，否则本地的服务自己也会被塞进代理
        self.assertIn("127.0.0.1", text)

    def test_strip_block_keeps_the_rest_verbatim(self):
        # 写入时不会额外插空行，所以撤销必须一字不差地还原
        text = ORIGINAL + sp._block(7890)
        self.assertEqual(sp.strip_block(text), ORIGINAL)

    def test_strip_block_on_text_without_block(self):
        self.assertEqual(sp.strip_block(ORIGINAL), ORIGINAL)

    def test_span_ignores_unpaired_marker(self):
        broken = "x\n" + sp.BLOCK0 + "\ny\n"
        self.assertIsNone(sp._span(broken.splitlines()))
        # 没有配对的结束标记时不能删东西，否则等于从用户文件里砍掉一段
        self.assertEqual(sp.strip_block(broken), broken)

    def test_foreign_env_sees_outside_lines(self):
        text = ORIGINAL + 'export HTTPS_PROXY="http://127.0.0.1:1080"\n'
        self.assertEqual(sp.foreign_env(text), [4])

    def test_foreign_env_ignores_our_own_block(self):
        text = ORIGINAL + "\n" + sp._block(7890)
        self.assertEqual(sp.foreign_env(text), [])


class ApplyTests(Sandbox):
    def test_backup_removes_secret_without_changing_original_secret(self):
        secret_line = 'export ANTHROPIC_API_KEY="example-private-value"\n'
        self.rc.write_text(ORIGINAL + secret_line, encoding="utf-8")
        out = self.apply()
        self.assertNotIn("example-private-value", Path(out["backup"]).read_text())
        self.assertIn(secret_line, self.rc.read_text())
        sp.undo()
        self.assertEqual(self.rc.read_text(), ORIGINAL + secret_line)

    def test_apply_appends_block_and_records_state(self):
        out = self.apply()
        text = self.rc.read_text(encoding="utf-8")
        self.assertIn(sp.BLOCK0, text)
        self.assertIn("http://127.0.0.1:7890", text)
        self.assertTrue(text.startswith("# 我原来的配置"))
        self.assertTrue(out["applied"])
        self.assertEqual(out["port"], 7890)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["port"], 7890)
        self.assertEqual(saved["file"], str(self.rc))
        mode = stat.S_IMODE(os.stat(self.state).st_mode)
        self.assertEqual(mode, 0o600)

    def test_apply_keeps_a_backup_of_the_original(self):
        out = self.apply()
        backup = Path(out["backup"])
        self.assertTrue(backup.is_file())
        self.assertEqual(backup.read_text(encoding="utf-8"), ORIGINAL)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)

    def test_apply_refuses_when_port_is_dead(self):
        with self.assertRaises(ValueError):
            sp.apply(7890, prober=lambda p: {"ok": False, "error": "端口没开"})
        # 没测通就不能动文件，也不能留记录
        self.assertEqual(self.rc.read_text(encoding="utf-8"), ORIGINAL)
        self.assertFalse(self.state.exists())

    def test_apply_refuses_when_someone_else_configured_it(self):
        self.rc.write_text(ORIGINAL + 'export HTTPS_PROXY="http://127.0.0.1:1080"\n',
                           encoding="utf-8")
        before = self.rc.read_text(encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            self.apply()
        self.assertIn("已经有代理变量", str(ctx.exception))
        self.assertEqual(self.rc.read_text(encoding="utf-8"), before)

    def test_apply_refuses_twice(self):
        self.apply()
        with self.assertRaises(ValueError):
            self.apply()

    def test_apply_refuses_bad_port(self):
        for bad in (0, 70000, "abc", None, -1):
            with self.assertRaises(ValueError):
                sp.apply(bad, prober=lambda p: {"ok": True})

    def test_apply_creates_the_file_when_missing(self):
        self.rc.unlink()
        self.apply(1087)
        text = self.rc.read_text(encoding="utf-8")
        self.assertIn("1087", text)
        self.assertNotIn("\n\n\n", text)


class UndoTests(Sandbox):
    def test_undo_restores_the_original_byte_for_byte(self):
        self.apply()
        out = sp.undo()
        self.assertEqual(self.rc.read_text(encoding="utf-8"), ORIGINAL)
        self.assertFalse(self.state.exists())
        self.assertFalse(out["applied"])

    def test_undo_without_record_is_refused(self):
        with self.assertRaises(ValueError):
            sp.undo()

    def test_undo_when_block_was_removed_by_hand(self):
        self.apply()
        self.rc.write_text(ORIGINAL, encoding="utf-8")
        out = sp.undo()
        # 块已经不在了：只清记录，不报错，也不动文件
        self.assertEqual(self.rc.read_text(encoding="utf-8"), ORIGINAL)
        self.assertFalse(self.state.exists())
        self.assertIn("已经不在", out["message"])

    def test_undo_keeps_lines_added_after_our_block(self):
        self.apply()
        text = self.rc.read_text(encoding="utf-8")
        self.rc.write_text(text + "export LATER=1\n", encoding="utf-8")
        sp.undo()
        self.assertEqual(self.rc.read_text(encoding="utf-8"), ORIGINAL + "export LATER=1\n")


class StatusTests(Sandbox):
    def test_status_before_apply(self):
        out = sp.status()
        self.assertTrue(out["canApply"])
        self.assertFalse(out["applied"])
        self.assertFalse(out["canUndo"])

    def test_status_after_apply(self):
        self.apply()
        out = sp.status()
        self.assertTrue(out["applied"])
        self.assertTrue(out["canUndo"])
        self.assertFalse(out["canApply"])
        self.assertIn(sp.BLOCK0, out["block"])

    def test_status_reports_foreign_lines_and_blocks_apply(self):
        self.rc.write_text(ORIGINAL + 'export http_proxy="http://127.0.0.1:1080"\n',
                           encoding="utf-8")
        out = sp.status()
        self.assertEqual(out["foreign"], [4])
        self.assertFalse(out["canApply"])

    def test_status_survives_a_broken_record(self):
        self.state.write_text("{ 不是 json", encoding="utf-8")
        out = sp.status()
        self.assertTrue(out["error"])
        self.assertFalse(out["canUndo"])
        self.assertFalse(out["canApply"])

    def test_status_when_shell_is_fish(self):
        with patch.object(sp, "rc_path", lambda: (None, "fish 的变量语法是 set -x")):
            out = sp.status()
        self.assertFalse(out["supported"])
        self.assertIn("fish", out["error"])
        self.assertFalse(out["canApply"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
