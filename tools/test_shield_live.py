#!/usr/bin/env python3
"""哨兵写下的「最近一轮巡检」，以及塔怎么用它。

塔只在自己被按下时看一眼世界，两次扫描之间发生的事它一概不知道；哨兵每
十秒看一次，却只有菜单栏那一小块地方能说话。这份文件就是接上两边的桥。

要固定下来的几条：

1. 过期的结论一律当没有。拿一份几小时前的「安全」当现状，正好把最该知道
   的空窗期盖住——比没有结论更误导。
2. 只对塔自己看不到的东西扣分（Claude 正在直连、代理开着却没接管）。
   WebRTC / DNS / 时区那几条塔自己有判据，哨兵的证据并进对应条目里，
   不再扣一次分：同一个问题罚两遍，用户会觉得「怎么修都掉血」。
3. 泄漏取并集。哨兵十秒看一次，比扫描那一刻的单次快照更容易撞上分裂；
   漏报的代价远大于误报。
4. 这个文件可能是手改的，任何字段都不能假设类型正确。

    python3 tools/test_shield_live.py
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import scanner, shield


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.file = self.tmp / "shield.json"
        p = mock.patch.object(shield, "STATE_FILE", self.file)
        p.start()
        self.addCleanup(p.stop)

    def write(self, payload: dict) -> None:
        self.file.write_text(json.dumps(payload), encoding="utf-8")

    def live_of(self, **live) -> dict:
        row = {"at": time.time(), "verdict": "safe", "title": "守护中",
               "note": "一切正常", "claudeRunning": True, "exitReady": True}
        row.update(live)
        self.write({"live": row})
        return shield.live()


class ReadTests(Base):
    def test_missing_file_is_not_available(self):
        out = shield.live()
        self.assertFalse(out["available"])
        self.assertFalse(out["fresh"])

    def test_live_absent_is_not_available(self):
        self.write({"baselineTz": "UTC"})
        self.assertFalse(shield.live()["available"])

    def test_fresh_row_is_parsed(self):
        out = self.live_of(directConnections=2, stunExposed=["1.2.*.4"])
        self.assertTrue(out["available"])
        self.assertTrue(out["fresh"])
        self.assertEqual(out["verdict"], "safe")
        self.assertEqual(out["directConnections"], 2)
        self.assertEqual(out["stunExposed"], ["1.2.*.4"])

    def test_old_row_is_available_but_not_fresh(self):
        out = self.live_of(at=time.time() - shield.LIVE_TTL - 60)
        self.assertTrue(out["available"])
        self.assertFalse(out["fresh"])
        self.assertGreater(out["age"], shield.LIVE_TTL)

    def test_bad_timestamp_is_not_available(self):
        for bad in (0, -1, "now", None):
            self.write({"live": {"at": bad, "verdict": "safe"}})
            self.assertFalse(shield.live()["available"], bad)

    def test_wrong_types_do_not_raise(self):
        out = self.live_of(directConnections="x", stunExposed="1.2.3.4",
                           ruleMissing=None, verdict=None)
        self.assertEqual(out["directConnections"], 0)
        self.assertEqual(out["stunExposed"], [])
        self.assertEqual(out["ruleMissing"], [])
        self.assertEqual(out["verdict"], "")

    def test_long_strings_are_truncated(self):
        out = self.live_of(note="x" * 900, title="y" * 900)
        self.assertEqual(len(out["note"]), 400)
        self.assertEqual(len(out["title"]), 200)

    def test_lists_are_capped(self):
        out = self.live_of(stunExposed=[f"1.2.*.{i}" for i in range(20)])
        self.assertEqual(len(out["stunExposed"]), 4)


class ItemTests(Base):
    """`shield.live` 这一项扣不扣分，扣在哪。"""

    def run_with(self, **kw) -> dict:
        return scanner._check_shield_live(self.live_of(**kw))

    def test_no_sentinel_is_info(self):
        item = scanner._check_shield_live(shield.live())
        self.assertEqual(item["severity"], "info")
        self.assertIn("没有哨兵的实时结论", item["title"])

    def test_stale_is_info_and_says_how_old(self):
        item = self.run_with(at=time.time() - 3600)
        self.assertEqual(item["severity"], "info")
        self.assertIn("分钟前", item["title"])

    def test_direct_connections_are_high(self):
        # 静态扫描永远扫不出来：配置可以全对，运行时却有一条路没被接管
        item = self.run_with(directConnections=3)
        self.assertEqual(item["severity"], "high")
        self.assertIn("3 条公网直连", item["title"])

    def test_takeover_missing_is_medium(self):
        item = self.run_with(takeoverMissing=True, verdict="warn")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("没接管", item["title"])

    def test_other_warnings_do_not_double_penalise(self):
        # DNS / WebRTC / 时区塔自己有判据，这里只当佐证
        item = self.run_with(verdict="warn", title="DNS 未接管", dnsSuspect=True)
        self.assertEqual(item["severity"], "info")
        self.assertIn("DNS 未接管", item["title"])

    def test_safe_is_pass(self):
        self.assertEqual(self.run_with()["severity"], "pass")

    def test_wired_into_scan(self):
        src = Path(scanner.__file__).read_text(encoding="utf-8")
        body = src[src.index("def check_network"):]
        body = body[:body.index("\ndef ")]
        self.assertIn("_check_shield_live", body)
        self.assertIn("shield.live()", body)


class WebRtcMergeTests(Base):
    """哨兵的 STUN 证据并进 `net.webrtc`，不另开一条。"""

    def stun(self, **over) -> dict:
        base = {"ips": ["5.34.220.136"], "foreign": ["5.34.220.136"],
                "exposed": [], "exposedLeak": False, "leak": False,
                "ok": True, "state": "pass", "mask": "5.34.*.136",
                "reason": "境外节点与基线一致"}
        base.update(over)
        return base

    def run_with(self, live: dict, **stun) -> dict:
        with mock.patch.object(scanner.stun, "probe", return_value=self.stun(**stun)):
            return scanner._check_webrtc("5.34.*.136", live)

    def test_scan_clean_stays_pass(self):
        self.assertEqual(self.run_with(self.live_of())["severity"], "pass")

    def test_shield_probe_exposure_is_high_without_browser_evidence(self):
        out = self.run_with(self.live_of(stunExposed=["112.97.*.112"]))
        self.assertEqual(out["severity"], "high")
        self.assertIn("112.97.*.112", out["detail"])
        self.assertIn("哨兵", out["detail"])

    def test_shield_leak_escalates_to_high(self):
        out = self.run_with(self.live_of(stunLeak=True))
        self.assertEqual(out["severity"], "high")
        self.assertIn("哨兵", out["detail"])

    def test_stale_shield_evidence_is_ignored(self):
        stale = self.live_of(at=time.time() - shield.LIVE_TTL - 60,
                             stunExposed=["112.97.*.112"], stunLeak=True)
        self.assertEqual(self.run_with(stale)["severity"], "pass")

    def test_both_sides_agreeing_do_not_duplicate_addresses(self):
        out = self.run_with(self.live_of(stunExposed=["112.97.*.112"]),
                            exposed=["112.97.32.112"], exposedLeak=True)
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["detail"].count("112.97.*.112"), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
