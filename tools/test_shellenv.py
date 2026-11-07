#!/usr/bin/env python3
"""终端环境变量对齐的测试。

全程在临时目录里跑：`apply` 会真的写文件，绝不能碰用户自己的 `.zshrc`。
所以 `shellenv.STATE` / `WRAPPER` 和 `shellproxy.rc_path` 都指向临时路径。

要固定下来的几条：

1. 标记块能读回来、能删干净，块外的内容一个字不动。
2. 块外已经有别人的 TZ/LANG 就不写——两块配置打架时谁生效不该由工具决定。
3. 回读不一致要改回原样，并且不留记录（留了就等于「永远撤不回来」）。
4. 我们自己建的文件，撤销后要删掉，不留空壳。

    python3 tools/test_shellenv.py
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import shellenv

RC_BODY = 'export PATH="$HOME/bin:$PATH"\nalias ll="ls -l"\n'


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.rc = self.tmp / ".zshrc"
        self.rc.write_text(RC_BODY, encoding="utf-8")
        self.patches = [
            mock.patch.object(shellenv, "STATE", self.tmp / "shellenv.json"),
            mock.patch.object(shellenv, "WRAPPER", self.tmp / "bin/claude-env"),
            mock.patch.object(shellenv.shellproxy, "rc_path",
                              return_value=(self.rc, "")),
            mock.patch.object(shellenv, "_backup", return_value="/tmp/fake.bak"),
            # apply/undo 会往操作日志里记一条，这里也得隔离，
            # 否则跑一次测试就往用户真实的 history.jsonl 里塞十几条假记录
            mock.patch.object(shellenv.history, "LOG",
                              self.tmp / "history.jsonl"),
            # 目标国家会去探实际出口。单元测试不碰网络，默认当作探不到，
            # 需要出口的用例自己覆盖这一层。
            mock.patch.object(shellenv.netprobe, "probe",
                              return_value={"available": False}),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def text(self):
        return self.rc.read_text(encoding="utf-8")


class TargetTests(unittest.TestCase):
    def test_known_country_resolves(self):
        t = shellenv.target("US")
        self.assertEqual(t["timezone"], "America/New_York")
        self.assertEqual(t["lang"], "en_US.UTF-8")
        self.assertTrue(t["resolved"])

    def test_japan(self):
        t = shellenv.target("JP")
        self.assertEqual(t["timezone"], "Asia/Tokyo")
        self.assertEqual(t["lang"], "ja_JP.UTF-8")

    def test_unknown_country_refuses_to_guess(self):
        t = shellenv.target("ZZ")
        self.assertFalse(t["resolved"])
        self.assertEqual(t["timezone"], "")

    def test_explicit_values_win(self):
        t = shellenv.target("US", timezone="Asia/Tokyo", locale="ja_JP")
        self.assertEqual(t["timezone"], "Asia/Tokyo")
        self.assertEqual(t["lang"], "ja_JP.UTF-8")


class BlockTests(unittest.TestCase):
    def test_render_and_read_back(self):
        vals = {"timezone": "America/New_York", "lang": "en_US.UTF-8",
                "lcAll": "en_US.UTF-8"}
        text = shellenv.render(vals)
        self.assertEqual(shellenv.block_values(text),
                         {"TZ": "America/New_York", "LANG": "en_US.UTF-8",
                          "LC_ALL": "en_US.UTF-8"})

    def test_strip_removes_only_the_block(self):
        vals = {"timezone": "Asia/Tokyo", "lang": "ja_JP.UTF-8",
                "lcAll": "ja_JP.UTF-8"}
        text = RC_BODY + shellenv.render(vals)
        self.assertEqual(shellenv.strip_block(text), RC_BODY)

    def test_strip_without_block_is_identity(self):
        self.assertEqual(shellenv.strip_block(RC_BODY), RC_BODY)

    def test_foreign_lines_ignore_our_block(self):
        vals = {"timezone": "Asia/Tokyo", "lang": "ja_JP.UTF-8",
                "lcAll": "ja_JP.UTF-8"}
        text = RC_BODY + shellenv.render(vals)
        self.assertEqual(shellenv.foreign_lines(text), [])

    def test_foreign_lines_found_outside_block(self):
        text = 'export LANG="zh_CN.UTF-8"\n' + RC_BODY
        self.assertEqual(shellenv.foreign_lines(text), [1])

    def test_language_var_counts_as_foreign(self):
        # LANGUAGE 是 gettext 的优先级链，留着中文界面语言照样是中文
        self.assertEqual(shellenv.foreign_lines('export LANGUAGE=zh\n'), [1])


class ApplyTests(Base):
    def test_apply_writes_block_and_keeps_rest(self):
        out = shellenv.apply("US")
        self.assertTrue(out["ok"])
        text = self.text()
        self.assertIn(shellenv.BLOCK0, text)
        self.assertIn(RC_BODY.strip().splitlines()[0], text)
        self.assertEqual(shellenv.block_values(text)["TZ"], "America/New_York")

    def test_apply_records_state_for_undo(self):
        shellenv.apply("US")
        self.assertTrue(shellenv.STATE.is_file())
        s = shellenv.status()
        self.assertTrue(s["applied"])
        self.assertTrue(s["canUndo"])
        self.assertFalse(s["canApply"])

    def test_apply_backs_up_existing_file(self):
        with mock.patch.object(shellenv, "_backup",
                               return_value="/tmp/b.bak") as m:
            shellenv.apply("US")
        m.assert_called_once()

    def test_apply_refuses_second_time(self):
        shellenv.apply("US")
        with self.assertRaises(ValueError) as ctx:
            shellenv.apply("JP")
        # 先撞到「已有未撤销的记录」；就算记录丢了，后面还有块检测兜着
        self.assertIn("未撤销", str(ctx.exception))

    def test_apply_refuses_when_foreign_env_present(self):
        self.rc.write_text('export LANG="zh_CN.UTF-8"\n' + RC_BODY, encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            shellenv.apply("US")
        self.assertIn("第 1 行", str(ctx.exception))
        # 拒绝之后文件不能被动过
        self.assertEqual(self.text(), 'export LANG="zh_CN.UTF-8"\n' + RC_BODY)

    def test_apply_refuses_unknown_country(self):
        with self.assertRaises(ValueError) as ctx:
            shellenv.apply("ZZ")
        self.assertIn("时区", str(ctx.exception))

    def test_apply_refuses_bad_timezone(self):
        with self.assertRaises(ValueError):
            shellenv.apply("US", timezone="../../etc/passwd")

    def test_readback_mismatch_rolls_back(self):
        # 让写入「成功」但内容没进去，模拟被别的程序覆盖
        with mock.patch.object(shellenv, "_write_text",
                               side_effect=lambda p, t: None):
            with self.assertRaises(RuntimeError) as ctx:
                shellenv.apply("US")
        self.assertIn("回读", str(ctx.exception))
        self.assertFalse(shellenv.STATE.exists(), "失败后不该留下记录")
        self.assertEqual(self.text(), RC_BODY)

    def test_creates_rc_when_missing(self):
        self.rc.unlink()
        shellenv.apply("US")
        self.assertTrue(self.rc.is_file())
        self.assertIn(shellenv.BLOCK0, self.text())

    def test_new_file_has_no_backup(self):
        self.rc.unlink()
        with mock.patch.object(shellenv, "_backup") as m:
            shellenv.apply("US")
        m.assert_not_called()


class UndoTests(Base):
    def test_undo_restores_original_text(self):
        shellenv.apply("US")
        out = shellenv.undo()
        self.assertTrue(out["ok"])
        self.assertEqual(self.text(), RC_BODY)
        self.assertFalse(shellenv.STATE.exists())

    def test_undo_without_record_refuses(self):
        with self.assertRaises(ValueError):
            shellenv.undo()

    def test_undo_deletes_file_we_created(self):
        self.rc.unlink()
        shellenv.apply("US")
        self.assertTrue(self.rc.is_file())
        shellenv.undo()
        self.assertFalse(self.rc.exists(), "整个文件都是我们写的，撤完该删掉")

    def test_undo_tolerates_manually_removed_block(self):
        shellenv.apply("US")
        self.rc.write_text(RC_BODY, encoding="utf-8")
        out = shellenv.undo()
        self.assertTrue(out["ok"])
        self.assertIn("已不在", out["message"])
        self.assertFalse(shellenv.STATE.exists())


class StatusTests(Base):
    def test_not_applied_yet(self):
        s = shellenv.status("US")
        self.assertFalse(s["applied"])
        self.assertTrue(s["canApply"])
        self.assertFalse(s["canUndo"])
        self.assertEqual(s["target"]["timezone"], "America/New_York")

    def test_foreign_blocks_apply(self):
        self.rc.write_text('export TZ="Asia/Shanghai"\n', encoding="utf-8")
        s = shellenv.status("US")
        self.assertFalse(s["canApply"])
        self.assertEqual(s["foreign"], [1])
        self.assertIn("已有别的", s["message"])

    def test_unresolvable_target_blocks_apply(self):
        s = shellenv.status("ZZ")
        self.assertFalse(s["canApply"])
        self.assertIn("推不出", s["message"])

    def test_unsupported_shell(self):
        with mock.patch.object(shellenv.shellproxy, "rc_path",
                               return_value=(None, "fish 不代写")):
            s = shellenv.status("US")
        self.assertFalse(s["supported"])
        self.assertIn("fish", s["reason"])


class RegressionTests(Base):
    def test_custom_values_cannot_inject_commands(self):
        for payload in ('en_US.UTF-8"; echo injected; #', 'en_US.$(id)', 'en_US.UTF-8\nexit'):
            with self.assertRaises(ValueError):
                shellenv.apply("US", locale=payload)
            with self.assertRaises(ValueError):
                shellenv.write_wrapper("US", locale=payload)
        with self.assertRaises(ValueError):
            shellenv.write_wrapper("US", timezone='America/New_York$(id)')
        self.assertEqual(self.rc.read_text(), RC_BODY)
        self.assertFalse(shellenv.WRAPPER.exists())

    def test_record_failure_rolls_back_original_file(self):
        with mock.patch.object(shellenv, "_write_state", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                shellenv.apply("US")
        self.assertEqual(self.rc.read_text(), RC_BODY)
        self.assertFalse(shellenv.STATE.exists())

    def test_record_failure_removes_new_file(self):
        self.rc.unlink()
        with mock.patch.object(shellenv, "_write_state", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                shellenv.apply("US")
        self.assertFalse(self.rc.exists())


class WrapperTests(Base):
    def test_wrapper_is_executable_and_execs(self):
        out = shellenv.write_wrapper("JP")
        path = Path(out["path"])
        self.assertTrue(path.is_file())
        self.assertTrue(path.stat().st_mode & 0o100, "启动器要可执行")
        body = path.read_text(encoding="utf-8")
        self.assertIn('TZ=Asia/Tokyo', body)
        self.assertIn('LANG=ja_JP.UTF-8', body)
        self.assertIn('exec "$@"', body)
        self.assertTrue(body.startswith("#!/bin/sh"))

    def test_wrapper_refuses_unknown_country(self):
        with self.assertRaises(ValueError):
            shellenv.write_wrapper("ZZ")


class EgressTargetTests(unittest.TestCase):
    """目标国家从哪来：调用方 → 预期国家 → 实际出口。

    预期排在出口前面是有意的。出口是「此刻」，预期是「长期」：代理关掉的
    那几分钟里出口会掉回本地，这时按出口写会把用户想摆脱的状态原样写回去。
    出口只在没设预期时兜底，让第一次用的人也能推得出一个值。
    """

    def _env(self, probe, expected):
        return (mock.patch.object(shellenv.netprobe, "probe", return_value=probe),
                mock.patch.object(shellenv.netcfg, "expected_country",
                                  return_value=expected))

    def test_expected_beats_momentary_egress(self):
        # 设了美国、此刻从中国出去（代理没开）——不能写成 Asia/Shanghai
        a, b = self._env({"available": True, "country": "CN"}, "US")
        with a, b:
            t = shellenv.target()
        self.assertEqual(t["country"], "US")
        self.assertEqual(t["source"], "expected")
        self.assertEqual(t["timezone"], "America/New_York")
        self.assertEqual(t["lang"], "en_US.UTF-8")

    def test_egress_used_when_nothing_declared(self):
        a, b = self._env({"available": True, "country": "jp"}, "")
        with a, b:
            t = shellenv.target()
        self.assertEqual(t["country"], "JP")
        self.assertEqual(t["source"], "egress")
        self.assertEqual(t["timezone"], "Asia/Tokyo")

    def test_nothing_known_stays_unresolved(self):
        a, b = self._env({"available": True, "country": ""}, "")
        with a, b:
            t = shellenv.target()
        self.assertFalse(t["resolved"])
        self.assertEqual(t["timezone"], "")

    def test_probe_failure_falls_back_instead_of_raising(self):
        with mock.patch.object(shellenv.netprobe, "probe",
                               side_effect=OSError("boom")), \
                mock.patch.object(shellenv.netcfg, "expected_country",
                                  return_value=""):
            t = shellenv.target()
        self.assertFalse(t["resolved"])

    def test_explicit_is_marked_as_such(self):
        t = shellenv.target("SG")
        self.assertEqual(t["source"], "explicit")
        self.assertEqual(t["timezone"], "Asia/Singapore")

    def test_explicit_country_skips_the_probe(self):
        with mock.patch.object(shellenv.netprobe, "probe") as m:
            t = shellenv.target("JP")
        self.assertEqual(t["timezone"], "Asia/Tokyo")
        m.assert_not_called()


class GateTests(Base):
    """非 macOS 上不许动手。

    不能指望 `shellproxy.rc_path()` 返回空路径来挡：那只在「认不出这个
    shell」时成立，换个平台上恰好有 zsh，它就认得，然后会去写一个本工具
    并不支持的 rc。闸门必须写在入口。
    """

    def setUp(self):
        super().setUp()
        p = mock.patch.object(shellenv.compat, "IS_MAC", False)
        p.start()
        self.addCleanup(p.stop)

    def test_status_reports_unsupported(self):
        s = shellenv.status("US")
        self.assertFalse(s["supported"])
        self.assertFalse(s["canApply"])
        self.assertIn("macOS", s["reason"])

    def test_apply_refuses(self):
        with self.assertRaises(ValueError) as ctx:
            shellenv.apply("US")
        self.assertIn("macOS", str(ctx.exception))
        self.assertNotIn(shellenv.BLOCK0, self.text())

    def test_undo_refuses(self):
        with self.assertRaises(ValueError):
            shellenv.undo()

    def test_wrapper_refuses(self):
        with self.assertRaises(ValueError):
            shellenv.write_wrapper("US")
        self.assertFalse((self.tmp / "bin/claude-env").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
