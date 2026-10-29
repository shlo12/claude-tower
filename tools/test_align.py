#!/usr/bin/env python3
"""按出口对齐：算目标、执行、恢复。三样都打桩，不碰真实系统设置。

    python3 tools/test_align.py
"""

from __future__ import annotations

import json
import plistlib
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import align, regioncfg


class Env:
    """一整套假环境：出口、当前时区、当前区域格式、两个写入动作。"""

    def __init__(self, test, country="US", tz="America/Los_Angeles",
                 cur_tz="Asia/Taipei", cur_locale="zh-Hant_US",
                 expected="", tz_ok=True, available=True):
        self.country = country
        self.tz = tz
        self.cur_tz = cur_tz
        self.cur_locale = cur_locale
        self.expected = expected
        self.tz_ok = tz_ok
        self.available = available
        self.calls = []
        self.languages = ["zh-Hant-TW", "en"]
        self.region = {"locale": cur_locale, "canRestore": False, "previous": ""}
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for target, name, value in (
            (align.netprobe, "probe", self._probe),
            (align.netcfg, "expected_country", lambda: self.expected),
            (align.netcfg, "set_country", self._set_country),
            (align.compat, "timezone_name", lambda: self.cur_tz),
            (align.compat, "apply_timezone", self._apply_tz),
            (align.compat, "IS_MAC", True),
            (align, "_languages", lambda: self.languages),
            (align, "_set_languages", lambda v: setattr(self, "languages", v)),
            (regioncfg, "status", lambda: dict(self.region)),
            (regioncfg, "apply", self._apply_locale),
            (regioncfg, "restore", self._restore_locale),
            (align, "STATE", self.root / ".ccclean/align.json"),
        ):
            p = patch.object(target, name, value)
            p.start()
            test.addCleanup(p.stop)

    def _probe(self):
        if not self.available:
            return {"available": False}
        return {"available": True, "country": self.country, "timezone": self.tz,
                "ip_masked": "1.2.*.4", "source": "test"}

    def _set_country(self, value):
        self.calls.append(("country", value))
        self.expected = value
        return {}

    def _apply_tz(self, value):
        self.calls.append(("timezone", value))
        if not self.tz_ok:
            return False, "系统未完成修改（可能取消授权）"
        self.cur_tz = value
        return True, "已生效"

    def _apply_locale(self, region, locale):
        self.calls.append(("locale", locale))
        self.region.update({"locale": locale, "canRestore": True,
                            "previous": self.cur_locale})

    def _restore_locale(self):
        self.calls.append(("locale-restore", self.region["previous"]))
        self.region.update({"locale": self.region["previous"], "canRestore": False})


class LanguagePreferenceTests(unittest.TestCase):
    def test_reads_array_without_saving_other_global_preferences(self):
        out = SimpleNamespace(returncode=0, stdout=plistlib.dumps({"AppleLanguages": ["zh-Hant-TW", "en"], "other": "private"}))
        with patch.object(align.subprocess, "run", return_value=out):
            self.assertEqual(align._languages(), ["zh-Hant-TW", "en"])

    def test_write_is_array_and_verified(self):
        with patch.object(align.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(align, "_languages", return_value=["en-US", "zh-Hant-TW"]):
            align._set_languages(["en-US", "zh-Hant-TW"])
        self.assertEqual(run.call_args.args[0], ["defaults", "write", "-g", "AppleLanguages", "-array", "en-US", "zh-Hant-TW"])

    def test_absent_original_key_is_deleted_on_restore(self):
        with patch.object(align.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(align, "_languages", return_value=None):
            align._set_languages(None)
        self.assertEqual(run.call_args.args[0], ["defaults", "delete", "-g", "AppleLanguages"])


class StatusTests(unittest.TestCase):
    def test_rows_point_at_the_egress(self):
        Env(self)
        out = align.status()
        self.assertTrue(out["supported"])
        rows = {r["key"]: r for r in out["rows"]}
        self.assertEqual(rows["country"]["target"], "US")
        self.assertTrue(rows["country"]["needed"])          # 未设置 → 要写
        self.assertEqual(rows["timezone"]["target"], "America/Los_Angeles")
        self.assertTrue(rows["timezone"]["needsAdmin"])
        self.assertEqual(rows["locale"]["target"], "en_US")
        self.assertTrue(out["canApply"])

    def test_region_matches_but_format_differs_is_still_listed(self):
        """zh-Hant_US 的地区已经对上了，但网页读到的还是 zh-Hant-US。"""
        Env(self, cur_locale="zh-Hant_US")
        rows = {r["key"]: r for r in align.status()["rows"]}
        self.assertTrue(rows["locale"]["needed"])
        self.assertIn("格式仍是", rows["locale"]["note"])

    def test_nothing_to_do_when_everything_matches(self):
        env = Env(self, cur_tz="America/Los_Angeles", cur_locale="en_US", expected="US")
        env.languages = ["en-US"]
        out = align.status()
        self.assertFalse(any(r["needed"] for r in out["rows"]))
        self.assertFalse(out["canApply"])

    def test_no_egress_means_no_targets(self):
        Env(self, available=False)
        out = align.status()
        self.assertFalse(out["canApply"])
        self.assertEqual(out["egress"]["country"], "")
        rows = {r["key"]: r for r in out["rows"]}
        self.assertFalse(rows["country"]["needed"])
        self.assertIn("出口没探到", rows["country"]["note"])
        self.assertIn("出口没探到", rows["locale"]["note"])

    def test_locale_row_is_blocked_by_an_unrestored_record(self):
        env = Env(self)
        env.region["canRestore"] = True
        rows = {r["key"]: r for r in align.status()["rows"]}
        self.assertFalse(rows["locale"]["needed"])
        self.assertIn("先恢复", rows["locale"]["note"])


class ApplyTests(unittest.TestCase):
    def test_language_is_optional_and_preserves_fallback_languages(self):
        env = Env(self)
        rows = {r["key"]: r for r in align.status()["rows"]}
        self.assertTrue(rows["language"]["requiresOptIn"])
        align.apply(["language"], language="en-US")
        self.assertEqual(env.languages, ["en-US", "zh-Hant-TW", "en"])
        align.restore()
        self.assertEqual(env.languages, ["zh-Hant-TW", "en"])

    def test_invalid_later_input_does_not_partially_change_country(self):
        env = Env(self)
        with self.assertRaises(ValueError):
            align.apply(["country", "timezone"], "US", "bad; timezone")
        self.assertEqual(env.calls, [])

    def test_failed_language_write_keeps_original_record(self):
        env = Env(self)
        with patch.object(align, "_set_languages", side_effect=RuntimeError("write failed")):
            with self.assertRaises(RuntimeError):
                align.apply(["language"], language="en-US")
        self.assertEqual(json.loads(align.STATE.read_text())["language"]["from"], env.languages)

    def test_language_restore_does_not_overwrite_manual_changes(self):
        env = Env(self)
        align.apply(["language"], language="en-US")
        env.languages = ["ja-JP"]
        with self.assertRaises(RuntimeError):
            align.restore()
        self.assertEqual(env.languages, ["ja-JP"])
        self.assertTrue(align.STATE.exists())

    def test_recovery_record_exists_before_first_write(self):
        Env(self)
        with patch.object(align.netcfg, "set_country", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                align.apply(["country"], "US")
        self.assertEqual(json.loads(align.STATE.read_text())["country"]["from"], "")

    def test_apply_country_timezone_locale_in_order(self):
        env = Env(self)
        out = align.apply(["country", "timezone", "locale"], "US",
                          "America/Los_Angeles", "en_US")
        self.assertEqual(env.calls, [("country", "US"),
                                     ("timezone", "America/Los_Angeles"),
                                     ("locale", "en_US")])
        self.assertTrue(all(r["ok"] for r in out["results"]))
        self.assertEqual(len(out["results"]), 3)
        saved = json.loads(align.STATE.read_text(encoding="utf-8"))
        self.assertEqual(saved["country"], {"from": "", "to": "US"})
        self.assertEqual(saved["timezone"],
                         {"from": "Asia/Taipei", "to": "America/Los_Angeles"})
        self.assertEqual(stat.S_IMODE(align.STATE.stat().st_mode), 0o600)
        self.assertTrue(out["canRestore"])

    def test_skipped_item_is_not_recorded(self):
        env = Env(self, expected="US", cur_tz="America/Los_Angeles")
        out = align.apply(["country", "timezone"], "US", "America/Los_Angeles")
        self.assertTrue(all(r["skipped"] for r in out["results"]))
        self.assertFalse(align.STATE.exists())
        self.assertEqual(env.calls, [])

    def test_cancelled_admin_auth_does_not_kill_the_rest(self):
        env = Env(self, tz_ok=False)
        out = align.apply(["timezone", "locale"], "", "America/Los_Angeles", "en_US")
        by_key = {r["key"]: r for r in out["results"]}
        self.assertFalse(by_key["timezone"]["ok"])
        self.assertTrue(by_key["locale"]["ok"])
        self.assertIn("授权", out["message"])
        saved = json.loads(align.STATE.read_text(encoding="utf-8"))
        self.assertNotIn("timezone", saved)     # 没改成的不能记成「改过」

    def test_all_failed_raises(self):
        Env(self, tz_ok=False)
        with self.assertRaises(RuntimeError):
            align.apply(["timezone"], "", "America/Los_Angeles", "")

    def test_bad_input_is_refused(self):
        env = Env(self)
        with self.assertRaises(ValueError):
            align.apply([], "US", "UTC", "en_US")
        with self.assertRaises(ValueError):
            align.apply(["country"], "USA", "", "")
        with self.assertRaises(ValueError):
            align.apply(["timezone"], "", "Los_Angeles", "")
        self.assertEqual(env.calls, [])
        self.assertFalse(align.STATE.exists())

    def test_second_apply_needs_a_restore(self):
        Env(self)
        align.apply(["country"], "US", "", "")
        with self.assertRaises(ValueError) as ctx:
            align.apply(["country"], "JP", "", "")
        self.assertIn("先恢复", str(ctx.exception))

    def test_symlink_state_is_refused(self):
        env = Env(self)
        align.STATE.parent.mkdir(parents=True, exist_ok=True)
        target = align.STATE.parent / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        align.STATE.symlink_to(target)
        with self.assertRaises(ValueError):
            align.apply(["country"], "US", "", "")
        self.assertEqual(env.calls, [])

    def test_corrupt_state_blocks_apply(self):
        env = Env(self)
        align.STATE.parent.mkdir(parents=True, exist_ok=True)
        align.STATE.write_text("{not json", encoding="utf-8")
        self.assertTrue(align.status()["error"])
        with self.assertRaises(ValueError):
            align.apply(["country"], "US", "", "")
        self.assertEqual(env.calls, [])


class RestoreTests(unittest.TestCase):
    def test_restore_reverses_everything(self):
        env = Env(self)
        align.apply(["country", "timezone", "locale"], "US",
                    "America/Los_Angeles", "en_US")
        env.calls.clear()
        out = align.restore()
        self.assertEqual(env.calls, [("locale-restore", "zh-Hant_US"),
                                     ("timezone", "Asia/Taipei"),
                                     ("country", "")])
        self.assertEqual(env.cur_tz, "Asia/Taipei")
        self.assertEqual(env.expected, "")
        self.assertFalse(align.STATE.exists())
        self.assertIn("恢复", out["message"])

    def test_restore_without_record_is_refused(self):
        Env(self)
        with self.assertRaises(ValueError):
            align.restore()

    def test_timezone_failure_keeps_the_record(self):
        env = Env(self)
        align.apply(["country", "timezone"], "US", "America/Los_Angeles", "")
        env.tz_ok = False
        with self.assertRaises(RuntimeError) as ctx:
            align.restore()
        self.assertIn("记录保留", str(ctx.exception))
        self.assertTrue(align.STATE.exists())

    def test_region_only_record_is_restorable(self):
        """只改过区域格式（在另一张卡片里改的）也能从这里恢复。"""
        env = Env(self)
        env.region.update({"locale": "en_US", "canRestore": True,
                           "previous": "zh-Hant_US"})
        out = align.restore()
        self.assertEqual(env.calls, [("locale-restore", "zh-Hant_US")])
        self.assertIn("区域格式", out["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
