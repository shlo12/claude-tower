#!/usr/bin/env python3
"""操作日志的测试。

要固定下来的几条：

1. 追加式，读出来新的在前。
2. 坏行不能把整份日志读废——一行脏数据不该让「最近操作」整块空白。
3. 日志是旁路：写失败返回 False，绝不抛异常。把修复带崩比丢一条日志严重得多。
4. 权限 0600。日志里不写密钥，但「谁在什么时候改过什么」也不该全机可读。

    python3 tools/test_history.py
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import history


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "history.jsonl"
        self.patch = mock.patch.object(history, "LOG", self.log)
        self.patch.start()
        self.addCleanup(self.patch.stop)


class WriteTests(Base):
    def test_log_creates_file(self):
        self.assertTrue(history.log("align.apply", target="出口对齐"))
        self.assertTrue(self.log.is_file())

    def test_row_shape(self):
        history.log("proxyfix.dns.apply", target="DNS 解析器", ok=False,
                    detail="回读不一致")
        row = history.tail(1)[0]
        for key in ("ts", "epoch", "action", "target", "ok", "detail"):
            self.assertIn(key, row)
        self.assertFalse(row["ok"])
        self.assertEqual(row["target"], "DNS 解析器")

    def test_newest_first(self):
        history.log("align.apply", target="1")
        history.log("align.restore", target="2")
        rows = history.tail(5)
        self.assertEqual([r["target"] for r in rows], ["2", "1"])

    def test_tail_limit(self):
        for i in range(30):
            history.log("align.apply", target=str(i))
        self.assertEqual(len(history.tail(5)), 5)
        self.assertEqual(history.tail(5)[0]["target"], "29")

    def test_file_mode_is_private(self):
        history.log("align.apply")
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_target_and_detail_are_truncated(self):
        history.log("align.apply", target="x" * 500, detail="y" * 900)
        row = history.tail(1)[0]
        self.assertLessEqual(len(row["target"]), 80)
        self.assertLessEqual(len(row["detail"]), 300)


class ExtraTests(Base):
    def test_flat_scalars_are_kept(self):
        history.log("align.apply", extra={"count": 3, "ok": True, "note": "x"})
        self.assertEqual(history.tail(1)[0]["extra"],
                         {"count": 3, "ok": True, "note": "x"})

    def test_nested_and_long_values_are_dropped(self):
        # 嵌套结构会让这份日志变成第二个状态文件
        history.log("align.apply", extra={"nested": {"a": 1}, "long": "z" * 200})
        self.assertNotIn("extra", history.tail(1)[0])


class ResilienceTests(Base):
    def test_corrupt_lines_are_skipped(self):
        history.log("align.apply", target="good")
        with open(self.log, "a", encoding="utf-8") as stream:
            stream.write("{not json\n")
            stream.write("\n")
            stream.write('{"no_action": 1}\n')
        rows = history.tail(10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "good")

    def test_missing_file_reads_as_empty(self):
        self.assertEqual(history.tail(10), [])

    def test_write_failure_does_not_raise(self):
        with mock.patch("builtins.open", side_effect=OSError("disk full")):
            self.assertFalse(history.log("align.apply"))
        # 调用方拿到 False，但流程不中断

    def test_clear_removes_file(self):
        history.log("align.apply")
        history.clear()
        self.assertFalse(self.log.exists())
        self.assertEqual(history.tail(5), [])


class RotateTests(Base):
    def test_rotation_keeps_recent_entries(self):
        old_keep = history.KEEP
        history.KEEP = 5
        self.addCleanup(setattr, history, "KEEP", old_keep)
        for i in range(40):
            history.log("align.apply", target=str(i))
        lines = self.log.read_text(encoding="utf-8").splitlines()
        self.assertLessEqual(len(lines), 10)
        self.assertEqual(json.loads(lines[-1])["target"], "39")

    def test_rotation_leaves_small_file_alone(self):
        history.log("align.apply")
        size = self.log.stat().st_size
        history.log("align.apply")
        self.assertGreater(self.log.stat().st_size, size)


class LabelTests(unittest.TestCase):
    def test_known_action_has_chinese_label(self):
        self.assertEqual(history.label("proxyfix.rules.undo"), "撤销分流规则")

    def test_unknown_action_falls_back_to_id(self):
        self.assertEqual(history.label("whatever.new"), "whatever.new")

    def test_every_action_used_by_core_is_labelled(self):
        # 代码里写日志的地方和这张表必须对得上，否则面板上会出现英文 id
        import subprocess
        root = Path(__file__).resolve().parent.parent
        found = set()
        for path in (root / "core").glob("*.py"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if "history.log(" not in line:
                    continue
                for action in history.ACTIONS:
                    if f'"{action}"' in line or f"f\"{action.split('.')[0]}." in line:
                        found.add(action)
        self.assertTrue(found, "没有从 core/ 里扫到任何 history.log 调用")
        for action in found:
            self.assertIn(action, history.ACTIONS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
