#!/usr/bin/env python3
"""按域名出口探测：trace 解析、打码、基线判定与扫描项接线。

这一项的价值全在「拿 Claude 自己的视角和出口探测比」：
解析错了、比对错了、或者把完整地址漏给上层，都会让结论变成编的。
所以这里既测纯函数，也测消费者拿到的严重度和证据。

    python3 tools/test_domainegress.py
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import domainegress as de  # noqa: E402
from core import scanner  # noqa: E402

A = "203.0.113.10"
B = "203.0.113.20"
C = "198.51.100.7"
V6 = "2001:db8::1"


def trace(ip: str, loc: str = "US", colo: str = "SJC") -> str:
    return (f"fl=1\nh=claude.ai\nip={ip}\nts=1\nvisit_scheme=https\n"
            f"uag=x\ncolo={colo}\nloc={loc}\ntls=TLSv1.3\n")


def row(host: str, ip: str, loc: str = "US") -> dict:
    return {"host": host, "ip": ip, "loc": loc, "colo": "SJC"}


class ParseTraceTests(unittest.TestCase):
    def test_reads_three_fields(self):
        r = de.parse_trace(trace(A, "us", "sjc"))
        self.assertEqual(r["ip"], A)
        self.assertEqual(r["loc"], "US")
        self.assertEqual(r["colo"], "SJC")

    def test_ignores_unknown_keys(self):
        r = de.parse_trace(trace(A))
        self.assertNotIn("ts", r)

    def test_rejects_bad_or_missing_ip(self):
        for body in ("", "ip=\nloc=US", "ip=not-an-ip\nloc=US",
                     "loc=US\ncolo=SJC", None, 123):
            self.assertIsNone(de.parse_trace(body), body)

    def test_ipv6_is_normalized(self):
        r = de.parse_trace(trace("2001:0db8::0001"))
        self.assertEqual(r["ip"], V6)


class AssessTests(unittest.TestCase):
    def test_match(self):
        r = de.assess([row("claude.ai", A), row("claude.com", A)], baseline_ip=A)
        self.assertEqual(r["state"], "match")
        self.assertTrue(r["checked"])

    def test_split_between_domains(self):
        r = de.assess([row("claude.ai", A), row("claude.com", B)], baseline_ip=A)
        self.assertEqual(r["state"], "split")

    def test_mismatch_against_baseline(self):
        r = de.assess([row("claude.ai", B), row("claude.com", B)], baseline_ip=A)
        self.assertEqual(r["state"], "mismatch")

    def test_no_baseline_does_not_guess(self):
        r = de.assess([row("claude.ai", A), row("claude.com", A)])
        self.assertEqual(r["state"], "unbaselined")
        self.assertTrue(r["checked"])

    def test_unavailable(self):
        r = de.assess([{"host": "claude.ai", "error": "x"},
                       {"host": "claude.com", "error": "y"}], baseline_ip=A)
        self.assertEqual(r["state"], "unavailable")
        self.assertFalse(r["checked"])

    def test_family_mismatch_is_not_a_leak(self):
        r = de.assess([row("claude.ai", V6), row("claude.com", V6)], baseline_ip=A)
        self.assertEqual(r["state"], "family")

    def test_partial_family_is_not_split(self):
        r = de.assess([row("claude.ai", A), row("claude.com", V6)], baseline_ip=A)
        self.assertEqual(r["state"], "partial")

    def test_one_domain_missing_is_not_a_match(self):
        r = de.assess([row("claude.ai", A), {"host": "claude.com", "error": "x"}],
                      baseline_ip=A)
        self.assertEqual(r["state"], "partial")
        self.assertIn("只取到一个", r["title"])

    def test_mask_baseline(self):
        r = de.assess([row("claude.ai", A), row("claude.com", A)],
                      baseline_mask="203.0.*.10")
        self.assertEqual(r["state"], "match")
        r = de.assess([row("claude.ai", B), row("claude.com", B)],
                      baseline_mask="203.0.*.10")
        self.assertEqual(r["state"], "mismatch")

    def test_full_ip_never_leaves_the_function(self):
        r = de.assess(
            [row("claude.ai", A), row("claude.com", B)],
            baseline_ip=C,
        )
        dumped = json.dumps(r, ensure_ascii=False)
        for ip in (A, B, C):
            self.assertNotIn(ip, dumped, ip)
        for item in r["rows"]:
            self.assertTrue(item["ipMasked"].endswith(".*." + item["ipMasked"].split(".")[-1]))
        self.assertEqual(r["domains"]["claude.ai"], "203.0.*.10")


class ProbeTests(unittest.TestCase):
    def test_fetches_every_domain_without_network(self):
        def fetcher(url):
            return trace(A)

        r = de.probe(baseline_ip=A, fetcher=fetcher)
        self.assertEqual(r["state"], "match")
        self.assertEqual(set(r["domains"]), {"claude.ai", "claude.com", "api.anthropic.com"})
        self.assertNotIn(A, json.dumps(r))

    def test_failure_and_malformed_are_kept_apart(self):
        def fetcher(url):
            if "claude.ai" in url:
                return None
            return "hello"

        r = de.probe(baseline_ip=A, fetcher=fetcher)
        self.assertEqual(r["state"], "unavailable")
        self.assertEqual(r["rows"][0]["error"], "请求失败")
        self.assertEqual(r["rows"][1]["error"], "响应格式不对")

    def test_exception_in_fetcher_does_not_escape(self):
        def fetcher(url):
            raise RuntimeError("boom")

        r = de.probe(baseline_ip=A, fetcher=fetcher)
        self.assertEqual(r["state"], "unavailable")

    def test_targets_are_fixed_claude_domains(self):
        self.assertEqual([h for h, _ in de.TARGETS],
                         ["claude.ai", "claude.com", "api.anthropic.com"])
        for host, url in de.TARGETS:
            self.assertTrue(url.startswith("https://" + host + "/"), url)
            self.assertTrue(url.endswith("/cdn-cgi/trace"))

    def test_module_does_not_persist(self):
        src = (ROOT / "core/domainegress.py").read_text(encoding="utf-8")
        for banned in ("write_text", "json.dump", "Path.home", "with open("):
            self.assertNotIn(banned, src, banned)

    def test_module_imports_work_in_slim_runtime(self):
        """内置运行时删掉了 concurrent 整个包，导入它会让整次扫描起不来。"""
        src = (ROOT / "core/domainegress.py").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(?m)^\s*(from|import)\s+concurrent\b", src))
        self.assertIsNotNone(re.search(r"(?m)^\s*import\s+threading\b", src))


class ScannerWiringTests(unittest.TestCase):
    def test_scanner_produces_item_in_both_paths(self):
        src = (ROOT / "core/scanner.py").read_text(encoding="utf-8")
        self.assertGreaterEqual(src.count('"net.domain_egress"'), 2,
                                "失败早退与正常路径都要有这一项")
        self.assertIn("domainegress.probe(", src)
        self.assertIn("_check_domain_egress(info)", src)

    def _item_for(self, state: str) -> dict:
        payload = {
            "state": state, "checked": state != "unavailable",
            "title": "标题", "detail": "说明",
            "rows": [{"host": "claude.ai", "ipMasked": "203.0.*.10", "loc": "US"}],
            "baselineMasked": "203.0.*.10",
            "domains": {"claude.ai": "203.0.*.10"},
        }
        with mock.patch.object(de, "probe", return_value=payload):
            return scanner._check_domain_egress({"ip": A, "ip_masked": "203.0.*.10"})

    def test_severity_follows_state(self):
        self.assertEqual(self._item_for("match")["severity"], "pass")
        self.assertEqual(self._item_for("split")["severity"], "high")
        self.assertEqual(self._item_for("mismatch")["severity"], "high")
        self.assertEqual(self._item_for("unavailable")["severity"], "info")
        self.assertEqual(self._item_for("unbaselined")["severity"], "info")
        self.assertEqual(self._item_for("partial")["severity"], "info")

    def test_consumer_evidence_is_masked(self):
        item = self._item_for("match")
        self.assertNotIn(A, json.dumps(item, ensure_ascii=False))
        self.assertEqual(item["category"], "network")
        self.assertIn("hard-signal", self._item_for("split")["tags"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
