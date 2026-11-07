#!/usr/bin/env python3
"""多源 IP 情报交叉验证的纯逻辑测试。

不联网：比对逻辑是纯函数，直接喂三家返回的字典。
真正要固定下来的是三件事：

1. 什么算「一致」，什么算「分歧」——判宽了等于没判，判严了会天天报警。
2. 同一件事的两种写法不能报成分歧（`United States` vs `US`、
   `AS4134` vs `AS4134 CHINANET BACKBONE`）。假阳性比漏报更伤人：
   用户会去改一个根本不存在的问题。
3. 解析器要同时认嵌套和扁平两种返回形状——ipapi.is 的免费层早就换成
   扁平了，只读嵌套会让国家、城市、时区全部变成 None。

    python3 tools/test_netprobe.py
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import netprobe


def row(source="ipapi.is", ip="1.2.3.4", country="US", asn="AS7849"):
    return {"source": source, "ip": ip, "country": country, "asn": asn}


class ConsensusTests(unittest.TestCase):
    def test_three_agreeing_sources_are_consistent(self):
        out = netprobe.consensus([
            row("ipapi.is"), row("ipwho.is"), row("ipinfo.io")])
        self.assertEqual(out["count"], 3)
        self.assertTrue(out["consistent"])
        self.assertEqual(out["disagree"], [])

    def test_country_disagreement_is_flagged(self):
        out = netprobe.consensus([
            row("ipapi.is", country="US"),
            row("ipwho.is", country="CA"),
        ])
        self.assertFalse(out["consistent"])
        fields = [d["field"] for d in out["disagree"]]
        self.assertIn("country", fields)

    def test_asn_disagreement_is_flagged(self):
        out = netprobe.consensus([
            row("ipapi.is", asn="AS7849"),
            row("ipwho.is", asn="AS15169"),
        ])
        self.assertFalse(out["consistent"])
        self.assertIn("asn", [d["field"] for d in out["disagree"]])

    def test_asn_spelling_variants_are_not_disagreement(self):
        # 同一家网络，一个源带上了运营方名字。这不是分歧。
        out = netprobe.consensus([
            row("ipapi.is", asn="AS4134 CHINANET BACKBONE"),
            row("ipwho.is", asn="AS4134"),
            row("ipinfo.io", asn="as 4134"),
        ])
        self.assertTrue(out["consistent"], out["disagree"])
        self.assertEqual(out["asns"], ["AS4134"])

    def test_country_name_and_code_are_not_disagreement(self):
        # 归一在解析层做，这里验证归一后的结果确实对得上。
        out = netprobe.consensus([
            row("ipapi.is", country=netprobe._country_code("United States")),
            row("ipwho.is", country=netprobe._country_code("US")),
        ])
        self.assertTrue(out["consistent"], out["disagree"])

    def test_single_source_does_not_claim_consistency_or_conflict(self):
        out = netprobe.consensus([row()])
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["disagree"], [])
        # 只有一家时「一致」和「不一致」都是编的；这里只要求不产生分歧项，
        # 判据那一层会用 count < 2 单独说明。
        self.assertTrue(out["consistent"])

    def test_empty_input_is_not_an_error(self):
        out = netprobe.consensus([])
        self.assertEqual(out["count"], 0)
        self.assertEqual(out["disagree"], [])

    def test_ip_change_is_reported_as_drift_not_disagreement(self):
        out = netprobe.consensus([
            row("ipapi.is", ip="1.2.3.4"),
            row("ipwho.is", ip="5.6.7.8"),
        ])
        self.assertTrue(out["drifted"])
        self.assertEqual([d["field"] for d in out["disagree"]], ["ip"])
        # 换了出口不等于情报源打架，不能判成 high
        self.assertTrue(out["consistent"])

    def test_missing_country_does_not_create_disagreement(self):
        out = netprobe.consensus([
            row("ipapi.is", country=""),
            row("ipwho.is", country="US"),
        ])
        self.assertTrue(out["consistent"], out["disagree"])

    def test_rows_without_ip_are_ignored(self):
        out = netprobe.consensus([
            row(), {"source": "broken", "ip": "", "country": "CA"},
        ])
        self.assertEqual(out["count"], 1)


class NormaliseTests(unittest.TestCase):
    def test_country_codes_pass_through(self):
        self.assertEqual(netprobe._country_code("us"), "US")
        self.assertEqual(netprobe._country_code("CN"), "CN")

    def test_country_names_map_to_codes(self):
        self.assertEqual(netprobe._country_code("United States"), "US")
        self.assertEqual(netprobe._country_code("United Kingdom"), "GB")
        self.assertEqual(netprobe._country_code("Hong Kong"), "HK")
        self.assertEqual(netprobe._country_code("Taiwan"), "TW")

    def test_unknown_country_is_not_guessed(self):
        # 认不出来就原样返回，不能编一个码出来
        self.assertEqual(netprobe._country_code("Atlantis"), "Atlantis")
        self.assertEqual(netprobe._country_code(""), "")

    def test_asn_key_extracts_number(self):
        self.assertEqual(netprobe._asn_key("AS15169 Google LLC"), "AS15169")
        self.assertEqual(netprobe._asn_key("as15169"), "AS15169")
        self.assertEqual(netprobe._asn_key("AS 4134"), "AS4134")

    def test_asn_key_gives_empty_for_junk(self):
        self.assertEqual(netprobe._asn_key(""), "")
        self.assertEqual(netprobe._asn_key("unknown"), "")


class ShapeTests(unittest.TestCase):
    """ipapi.is 免费层是扁平结构，完整版是嵌套结构，两种都得认。"""

    FLAT = {
        "ip": "8.8.8.8", "is_bogon": False,
        "company": "Google LLC", "asn": "AS15169 Google LLC",
        "city": "Mountain View", "region": "California",
        "country": "United States", "timezone": "America/Los_Angeles",
    }
    NESTED = {
        "ip": "8.8.8.8",
        "location": {"country": "United States", "country_code": "US",
                     "city": "Mountain View", "state": "California",
                     "timezone": "America/Los_Angeles"},
        "asn": {"asn": "AS15169", "org": "Google LLC", "type": "hosting"},
        "company": {"name": "Google LLC"},
        "is_datacenter": True,
    }

    def parse(self, payload):
        with mock.patch.object(netprobe, "_get", return_value=payload):
            return netprobe._from_ipapi_is()

    def test_flat_shape_yields_country_city_timezone(self):
        out = self.parse(self.FLAT)
        self.assertEqual(out["country"], "US")
        self.assertEqual(out["city"], "Mountain View")
        self.assertEqual(out["timezone"], "America/Los_Angeles")
        self.assertEqual(out["asn"], "AS15169")
        self.assertEqual(out["org"], "Google LLC")

    def test_flat_shape_still_guesses_hosting(self):
        out = self.parse(self.FLAT)
        self.assertTrue(out["hosting_guess"])

    def test_nested_shape_still_works(self):
        out = self.parse(self.NESTED)
        self.assertEqual(out["country"], "US")
        self.assertEqual(out["asn"], "AS15169")
        self.assertEqual(out["asn_type"], "hosting")
        self.assertTrue(out["is_datacenter"])

    def test_missing_ip_returns_none(self):
        self.assertIsNone(self.parse({"asn": "AS1"}))

    def test_probe_exposes_consensus_fields(self):
        primary = self.parse(self.FLAT)
        second = {"source": "ipwho.is", "ip": "8.8.8.8", "country": "US",
                  "asn": "AS15169", "city": "Mountain View",
                  "timezone": "America/Los_Angeles"}
        with mock.patch.object(netprobe, "probe_all",
                               return_value=[primary, second]):
            info = netprobe.probe()
        for key in ("sourceCount", "multiSourceConsistent", "sources",
                    "countries", "disagree", "drifted"):
            self.assertIn(key, info)
        self.assertEqual(info["sourceCount"], 2)
        self.assertTrue(info["multiSourceConsistent"], info["disagree"])
        self.assertEqual(info["country"], "US")
        self.assertEqual(info["source"], "ipapi.is")


class CacheTests(unittest.TestCase):
    def setUp(self):
        netprobe._cache["rows"] = None
        netprobe._cache["at"] = 0.0
        self.addCleanup(netprobe._cache.update, rows=None, at=0.0)

    def test_second_call_within_ttl_does_not_refetch(self):
        calls = []

        def fake():
            calls.append(1)
            return [row()]

        with mock.patch.object(netprobe, "_fetch_all", side_effect=fake):
            netprobe.probe_all()
            netprobe.probe_all()
        self.assertEqual(len(calls), 1)

    def test_force_refetches(self):
        calls = []

        def fake():
            calls.append(1)
            return [row()]

        with mock.patch.object(netprobe, "_fetch_all", side_effect=fake):
            netprobe.probe_all()
            netprobe.probe_all(force=True)
        self.assertEqual(len(calls), 2)

    def test_fetch_failure_degrades_to_empty(self):
        with mock.patch.object(netprobe, "_fetch_all", side_effect=RuntimeError("x")):
            self.assertEqual(netprobe.probe_all(), [])


class BoundedFetchTests(unittest.TestCase):
    def test_stalled_source_does_not_hold_scan_open(self):
        import threading
        import time
        release = threading.Event()
        def stalled():
            release.wait(2)
            return row(source="late")
        try:
            with mock.patch.object(netprobe, "_SOURCES", (stalled, lambda: row())):
                started = time.monotonic()
                rows = netprobe._fetch_all(timeout=0.03)
                self.assertLess(time.monotonic() - started, 0.5)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["source"], "ipapi.is")
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main(verbosity=2)
