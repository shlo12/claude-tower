#!/usr/bin/env python3
"""塔写给哨兵的基线。

只验一件事：塔每跑完一次扫描，写进 shield.json 的那两个键对不对、
有没有把哨兵自己的开关和命中记录踩掉。

全部在临时目录里跑，不碰真实的 ~/.ccclean。
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import shield


def scan(country="JP", tz="Asia/Tokyo", ip="5.34.*.136"):
    return {
        "network": {"available": True, "country": country, "ip": ip},
        "system": {"timezone": tz},
        "items": [],
    }


class BaselineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ccclean-shield-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / ".ccclean"
        self.file = self.dir / "shield.json"
        p = patch.multiple(shield, STATE_DIR=self.dir, STATE_FILE=self.file)
        p.start()
        self.addCleanup(p.stop)

    def test_writes_timezone_and_country(self):
        self.assertTrue(shield.write_baseline(scan(country="JP", tz="Asia/Tokyo")))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertEqual(data["baselineTz"], "Asia/Tokyo")
        self.assertEqual(data["country"], "JP")
        self.assertEqual(data["version"], 1)

    def test_preserves_keys_owned_by_shield(self):
        # 最关键的一条：塔不能把用户的开关、暂停时间和命中记录写没
        self.dir.mkdir(parents=True)
        self.file.write_text(json.dumps({
            "enabled": False, "level": 2, "pausedUntil": 12345,
            "hits": [{"ts": 1, "kind": "danger", "note": "x"}],
        }), encoding="utf-8")
        shield.write_baseline(scan(country="US", tz="America/New_York"))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertFalse(data["enabled"])
        self.assertEqual(data["level"], 2)
        self.assertEqual(data["pausedUntil"], 12345)
        self.assertEqual(len(data["hits"]), 1)
        self.assertEqual(data["country"], "US")

    def test_no_change_means_no_write(self):
        shield.write_baseline(scan(country="JP", tz="Asia/Tokyo"))
        before = self.file.stat().st_mtime_ns
        self.assertFalse(shield.write_baseline(scan(country="JP", tz="Asia/Tokyo")))
        self.assertEqual(self.file.stat().st_mtime_ns, before)

    def test_file_is_owner_only(self):
        shield.write_baseline(scan(country="JP", tz="Asia/Tokyo"))
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)

    def test_broken_file_does_not_raise(self):
        self.dir.mkdir(parents=True)
        self.file.write_text("{ not json", encoding="utf-8")
        self.assertTrue(shield.write_baseline(scan(country="JP", tz="Asia/Tokyo")))
        self.assertEqual(json.loads(self.file.read_text(encoding="utf-8"))["country"], "JP")

    def test_empty_scan_is_ignored(self):
        self.assertFalse(shield.write_baseline({}))
        self.assertFalse(self.file.exists())

    def test_missing_country_keeps_old_value(self):
        # 这次探测不到出口，不该把上次记的国家清成空
        shield.write_baseline(scan(country="JP", tz="Asia/Tokyo"))
        shield.write_baseline(scan(country="", tz="Asia/Tokyo"))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertEqual(data["country"], "JP")

    def test_status_reads_back(self):
        shield.write_baseline(scan(country="SG", tz="Asia/Singapore"))
        st = shield.status()
        self.assertEqual(st["baseline"]["country"], "SG")
        self.assertEqual(st["baseline"]["tz"], "Asia/Singapore")
        self.assertIn("installed", st["app"])
        self.assertIn("running", st["app"])

    def test_writes_masked_egress_ip(self):
        """Shield 靠这个地址跟 STUN 结果比对，判断 UDP 有没有走同一条路。"""
        shield.write_baseline(scan(ip="5.34.*.136"))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertEqual(data["egressIP"], "5.34.*.136")
        self.assertGreater(data["egressAt"], 0)

    def test_never_writes_a_full_ip(self):
        """塔从不把完整 IP 交给别人，包括自己的另一个程序。"""
        shield.write_baseline(scan(ip="5.34.*.136"))
        raw = self.file.read_text(encoding="utf-8")
        # 打码后的地址必须留着星号，不能有完整四段
        import re as _re
        self.assertIsNone(_re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw),
                          "shield.json 里出现了完整 IP")

    def test_missing_egress_keeps_old_value(self):
        shield.write_baseline(scan(ip="5.34.*.136"))
        shield.write_baseline(scan(ip=""))
        self.assertEqual(json.loads(self.file.read_text(encoding="utf-8"))["egressIP"],
                         "5.34.*.136")

    def test_egress_timestamp_is_throttled(self):
        """连着扫两次不该各写一次盘——打开页面就会扫。"""
        shield.write_baseline(scan())
        before = self.file.stat().st_mtime_ns
        self.assertFalse(shield.write_baseline(scan()))
        self.assertEqual(self.file.stat().st_mtime_ns, before)

    def test_status_reports_egress_age(self):
        shield.write_baseline(scan(ip="5.34.*.136"))
        st = shield.status()
        self.assertEqual(st["baseline"]["ip"], "5.34.*.136")
        self.assertIsNotNone(st["baseline"]["ipAge"])
        self.assertGreaterEqual(st["baseline"]["ipAge"], 0)

    def test_status_survives_missing_file(self):
        # 不能读真实进程表：开发机上可能正好开着仓库里的 Shield，
        # 这条测试就会变成「取决于今天开没开应用」。
        with patch.multiple(shield, running=lambda: False, installed=lambda: False,
                            launch_agent_state=lambda: "none"):
            st = shield.status()
        self.assertEqual(st["baseline"]["country"], "")
        self.assertFalse(st["app"]["running"])
        self.assertEqual(st["app"]["launchAgent"], "none")

    def test_shield_is_looked_for_inside_the_tower_bundle(self):
        """一个下载：不能再去找 /Applications 里的独立 Claude Shield.app。"""
        self.assertTrue(shield.APP_PATHS)
        for path in shield.APP_PATHS:
            self.assertIn("Claude Tower.app/Contents/Resources/Claude Shield.app",
                          str(path))
        tmp = Path(tempfile.mkdtemp(prefix="ccclean-nested-"))
        try:
            nested = tmp / "Claude Tower.app/Contents/Resources/Claude Shield.app"
            nested.mkdir(parents=True)
            with patch.object(shield, "APP_PATHS", (nested,)):
                self.assertTrue(shield.installed())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_rule_guard_records_only_rule_pairs(self):
        """哨兵按 `TYPE,payload` 核对，策略名可能被客户端重写，不记第三段。"""
        self.assertTrue(shield.record_rule_guard(
            "flclash", "FlClash 运行配置", "/tmp/config.yaml",
            ["DOMAIN-SUFFIX,claude.ai,PROXY", "DST-PORT,443,DIRECT"]))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        guard = data["ruleGuard"]
        self.assertEqual(guard["client"], "flclash")
        self.assertEqual(guard["path"], "/tmp/config.yaml")
        self.assertEqual(guard["rules"], ["DOMAIN-SUFFIX,claude.ai", "DST-PORT,443"])
        self.assertGreater(guard["at"], 0)

    def test_rule_guard_is_not_clobbered_by_baseline_write(self):
        shield.record_rule_guard("clashx", "ClashX config.yaml",
                                 "/tmp/config.yaml", ["DOMAIN-SUFFIX,claude.ai,PROXY"])
        shield.write_baseline(scan(country="JP", tz="Asia/Tokyo"))
        data = json.loads(self.file.read_text(encoding="utf-8"))
        self.assertIn("ruleGuard", data)
        self.assertEqual(data["country"], "JP")

    def test_undo_clears_rule_guard(self):
        """用户主动撤销修复后，哨兵不该继续报「规则不见了」。"""
        shield.record_rule_guard("flclash", "x", "/tmp/config.yaml",
                                 ["DOMAIN-SUFFIX,claude.ai,PROXY"])
        self.assertTrue(shield.clear_rule_guard())
        self.assertNotIn("ruleGuard",
                         json.loads(self.file.read_text(encoding="utf-8")))
        self.assertFalse(shield.clear_rule_guard())

    def test_rule_guard_without_rules_is_ignored(self):
        self.assertFalse(shield.record_rule_guard("flclash", "x", "/tmp/config.yaml", []))
        self.assertFalse(self.file.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
