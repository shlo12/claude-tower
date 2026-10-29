#!/usr/bin/env python3
"""区域格式（AppleLocale）：解析、写入、恢复。全部对着假的 defaults 跑。

    python3 tools/test_regioncfg.py
"""

from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import regioncfg


class FakeDefaults:
    """替身：只认 read/write -g AppleLocale 这两条命令，别的都不该出现。"""

    def __init__(self, value="zh_CN", accept=True):
        self.value = value
        self.accept = accept
        self.calls = []

    def __call__(self, args, timeout=6):
        self.calls.append(list(args))
        if args[:3] == ["defaults", "read", "-g"]:
            return self.value
        if args[:3] == ["defaults", "write", "-g"]:
            if self.accept:
                self.value = args[4]
            return ""
        raise AssertionError(f"不该调用：{args}")


class ParseTests(unittest.TestCase):
    def test_region_comes_from_the_second_part(self):
        self.assertEqual(regioncfg.parse_region("zh_CN"), "CN")
        self.assertEqual(regioncfg.parse_region("en-GB"), "GB")
        self.assertEqual(regioncfg.parse_region("zh-Hans_CN"), "CN")
        self.assertEqual(regioncfg.parse_region("en_US@rg=uszzzz"), "US")
        self.assertEqual(regioncfg.parse_region("sr_Latn_RS"), "RS")

    def test_language_alone_is_not_a_region(self):
        # "en" 是语言不是地区，拿它去跟出口国家比会得出荒谬结论
        for value in ("en", "", "  ", "C", "POSIX"):
            self.assertEqual(regioncfg.parse_region(value), "", value)

    def test_locale_for_known_and_unknown(self):
        self.assertEqual(regioncfg.locale_for("us"), "en_US")
        self.assertEqual(regioncfg.locale_for("JP"), "ja_JP")
        self.assertEqual(regioncfg.locale_for("CN"), "zh_CN")
        self.assertEqual(regioncfg.locale_for("ZZ"), "en_ZZ")
        self.assertEqual(regioncfg.locale_for(""), "")
        self.assertEqual(regioncfg.locale_for("USA"), "")

    def test_every_mapped_locale_parses_back(self):
        for region, locale in regioncfg.LOCALES.items():
            self.assertEqual(regioncfg.parse_region(locale), region, locale)


class ApplyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.state = root / ".ccclean/region.json"
        for name, value in (("STATE", self.state), ("IS_MAC", True)):
            p = patch.object(regioncfg if name == "STATE" else regioncfg.compat,
                             name, value)
            p.start()
            self.addCleanup(p.stop)

    def use(self, fake):
        p = patch.object(regioncfg, "_run", fake)
        p.start()
        self.addCleanup(p.stop)
        return fake

    def test_apply_writes_one_key_and_records_previous(self):
        fake = self.use(FakeDefaults("zh_CN"))
        out = regioncfg.apply("US")
        self.assertEqual(fake.value, "en_US")
        self.assertEqual(out["locale"], "en_US")
        self.assertEqual(out["region"], "US")
        self.assertEqual(out["previous"], "zh_CN")
        self.assertTrue(out["canRestore"])
        # 只碰 AppleLocale 一个键：系统语言和时区都不该出现在命令里
        writes = [c for c in fake.calls if c[:2] == ["defaults", "write"]]
        self.assertEqual(writes, [["defaults", "write", "-g", "AppleLocale", "en_US"]])
        self.assertTrue(all("AppleLanguages" not in c for c in fake.calls))
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["previous"], "zh_CN")
        self.assertEqual(saved["locale"], "en_US")

    def test_restore_puts_the_old_value_back(self):
        fake = self.use(FakeDefaults("zh_CN"))
        regioncfg.apply("JP")
        self.assertEqual(fake.value, "ja_JP")
        out = regioncfg.restore()
        self.assertEqual(fake.value, "zh_CN")
        self.assertEqual(out["locale"], "zh_CN")
        self.assertFalse(out["canRestore"])
        self.assertFalse(self.state.exists())

    def test_restore_accepts_a_hyphenated_original(self):
        """本机真实值可能是 `zh-Hant_US` 这种混写，恢复要原样写回去。"""
        fake = self.use(FakeDefaults("zh-Hant_US"))
        regioncfg.apply("JP")
        regioncfg.restore()
        self.assertEqual(fake.value, "zh-Hant_US")

    def test_apply_is_idempotent_when_already_there(self):
        fake = self.use(FakeDefaults("en_US"))
        out = regioncfg.apply("US")
        self.assertIn("已经是", out["message"])
        self.assertFalse(self.state.exists())
        self.assertEqual([c for c in fake.calls if c[:2] == ["defaults", "write"]], [])

    def test_second_apply_needs_a_restore_first(self):
        self.use(FakeDefaults("zh_CN"))
        regioncfg.apply("US")
        with self.assertRaises(ValueError) as ctx:
            regioncfg.apply("JP")
        self.assertIn("先恢复", str(ctx.exception))

    def test_bad_input_is_refused(self):
        fake = self.use(FakeDefaults("zh_CN"))
        for region in ("", "USA", "1S", None):
            with self.assertRaises(ValueError):
                regioncfg.apply(region)
        with self.assertRaises(ValueError):
            regioncfg.apply("US", "en_US_POSIX")     # 不是 语言_地区 的形状
        with self.assertRaises(ValueError):
            regioncfg.apply("US", "ja_JP")           # 和地区对不上
        self.assertEqual(fake.value, "zh_CN")
        self.assertFalse(self.state.exists())

    def test_write_that_does_not_stick_is_reported(self):
        self.use(FakeDefaults("zh_CN", accept=False))
        with self.assertRaises(RuntimeError):
            regioncfg.apply("US")
        # 没生效就不能留记录，否则用户会以为「改过了，只是没显示」
        self.assertFalse(self.state.exists())

    def test_unreadable_current_value_is_refused(self):
        self.use(FakeDefaults(""))
        with self.assertRaises(ValueError) as ctx:
            regioncfg.apply("US")
        self.assertIn("读不到", str(ctx.exception))

    def test_symlink_state_is_refused(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        target = self.state.parent / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.state.symlink_to(target)
        self.use(FakeDefaults("zh_CN"))
        with self.assertRaises(ValueError):
            regioncfg.apply("US")

    def test_corrupt_state_blocks_apply(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("{not json", encoding="utf-8")
        self.use(FakeDefaults("zh_CN"))
        out = regioncfg.status()
        self.assertTrue(out["error"])
        self.assertFalse(out["canRestore"])
        with self.assertRaises(ValueError):
            regioncfg.apply("US")

    def test_restore_without_record_is_refused(self):
        self.use(FakeDefaults("zh_CN"))
        with self.assertRaises(ValueError):
            regioncfg.restore()

    def test_not_macos_is_refused(self):
        self.use(FakeDefaults("zh_CN"))
        with patch.object(regioncfg.compat, "IS_MAC", False):
            out = regioncfg.status()
            self.assertFalse(out["supported"])
            self.assertEqual(out["locale"], "")
            with self.assertRaises(ValueError):
                regioncfg.apply("US")


class ScannerItemTests(unittest.TestCase):
    """扫描里的那一项：只报告，不动手。"""

    def item(self, raw, country="", expected=""):
        from core import scanner
        # 两处都打桩：传进来的值优先，读不到时扫描会自己再读一次，
        # 那一处也得是同一个值，否则测的就不是「读不到」这条分支了。
        with patch.object(scanner.netcfg, "expected_country", lambda: expected), \
                patch.object(scanner, "_system_locale", lambda: raw), \
                patch.object(scanner, "_system_timezone", lambda: "Asia/Shanghai"):
            return scanner._check_region_format({"country": country}, raw)

    def test_match_is_pass(self):
        it = self.item("en_US", "US")
        self.assertEqual(it["id"], "locale.region")
        self.assertEqual(it["severity"], "pass")
        self.assertIsNone(it["fix"])

    def test_mismatch_is_medium_and_names_both_sides(self):
        it = self.item("zh_CN", "US")
        self.assertEqual(it["severity"], "medium")
        self.assertIn("CN", it["title"])
        self.assertIn("US", it["title"])
        self.assertIn("Intl.DateTimeFormat", it["detail"])
        # 只给建议，不给「加入清理清单」——它不是一个可以删的东西
        self.assertIsNone(it["fix"])

    def test_falls_back_to_expected_country(self):
        it = self.item("zh_CN", "", expected="JP")
        self.assertEqual(it["severity"], "medium")
        self.assertIn("JP", it["title"])

    def test_no_region_is_info(self):
        it = self.item("", "US")
        self.assertEqual(it["severity"], "info")

    def test_no_target_is_info(self):
        it = self.item("zh_CN", "", "")
        self.assertEqual(it["severity"], "info")
        self.assertIn("CN", it["title"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
