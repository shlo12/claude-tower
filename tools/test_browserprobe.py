#!/usr/bin/env python3
"""浏览器侧实测的两块逻辑：ICE 候选判定 + 安全 DNS 判定。

这两项都碰不到真网络也能测：候选行是纯字符串，浏览器配置是纯文件，
判定函数是纯函数。真正需要浏览器的部分（收集候选）在页面里，
这里只保证「拿到的候选怎么解释」和「读到的配置怎么解释」是固定的。

    python3 tools/test_browserprobe.py
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import browserwebrtc as bw  # noqa: E402
from core import doh  # noqa: E402


def cand(ip, typ="host", port=50000, proto="udp"):
    return (f"candidate:1 1 {proto} 2122260223 {ip} {port} typ {typ} "
            f"raddr 0.0.0.0 rport 0 generation 0")


class ParseCandidateTests(unittest.TestCase):
    def test_with_prefix(self):
        c = bw.parse_candidate(cand("192.168.1.100"))
        self.assertEqual(c["ip"], "192.168.1.100")
        self.assertEqual(c["typ"], "host")
        self.assertEqual(c["protocol"], "udp")

    def test_without_prefix(self):
        # 某些 polyfill 给的字符串不带 candidate: 前缀，按位置取字段才稳
        c = bw.parse_candidate(cand("10.0.0.2")[len("candidate:"):])
        self.assertEqual(c["ip"], "10.0.0.2")

    def test_srflx(self):
        c = bw.parse_candidate(cand(PUB, "srflx"))
        self.assertEqual(c["typ"], "srflx")

    def test_mdns_host(self):
        c = bw.parse_candidate(cand("8f2e1b3a-1111.local"))
        self.assertTrue(c["ip"].endswith(".local"))

    def test_ipv6(self):
        c = bw.parse_candidate(cand("2001:db8::1", "srflx"))
        self.assertEqual(c["ip"], "2001:db8::1")

    def test_garbage_returns_none(self):
        for bad in ("", "   ", "candidate:", "hello world", None, 123,
                    "candidate:1 1 udp 1 1.2.3.4 5 typ"):
            self.assertIsNone(bw.parse_candidate(bad), bad)


class SummarizeTests(unittest.TestCase):
    def test_splits_by_type(self):
        s = bw.summarize([
            cand("192.168.1.5"),
            cand(PUB, "srflx"),
            cand(OTHER, "relay"),
        ])
        self.assertEqual(s["host"], ["192.168.1.5"])
        self.assertEqual(s["srflx"], [PUB])
        self.assertEqual(s["relay"], [OTHER])
        self.assertEqual(s["private"], ["192.168.1.5"])

    def test_mdns_counted_not_stored_as_ip(self):
        s = bw.summarize([cand("aaa.local"), cand("bbb.local")])
        self.assertEqual(s["mdns"], 2)
        self.assertEqual(s["host"], [])

    def test_dedupes(self):
        s = bw.summarize([cand(PUB, "srflx"), cand(PUB, "srflx")])
        self.assertEqual(s["srflx"], [PUB])

    def test_non_list_is_empty(self):
        self.assertEqual(bw.summarize(None)["srflx"], [])
        self.assertEqual(bw.summarize("nope")["srflx"], [])

    def test_public_host_not_marked_private(self):
        s = bw.summarize([cand(PUB)])
        self.assertEqual(s["private"], [])


PUB = "93.184.216.34"
OTHER = "45.33.32.156"
V6 = "2408:8207:8990:5c10::1"
MASK = "93.184.*.34"


class AssessTests(unittest.TestCase):
    def _s(self, **kw):
        base = {"host": [], "srflx": [], "relay": [], "mdns": 0, "private": []}
        base.update(kw)
        return base

    def test_match_is_pass(self):
        v = bw.assess(self._s(srflx=[PUB]), MASK, 60)
        self.assertEqual(v["state"], "pass")

    def test_split_is_leak(self):
        v = bw.assess(self._s(srflx=[PUB, OTHER]), MASK, 60)
        self.assertEqual(v["state"], "leak")
        self.assertIn("两个", v["title"])

    def test_mismatch_fresh_is_leak(self):
        v = bw.assess(self._s(srflx=[OTHER]), MASK, 60)
        self.assertEqual(v["state"], "leak")

    def test_ipv6_only_with_ipv4_baseline_is_unknown(self):
        # 地址族不同没法比对；判成泄漏就是编结论
        v = bw.assess(self._s(srflx=[V6]), MASK, 60)
        self.assertEqual(v["state"], "unknown")
        self.assertIn("IPv6", v["title"])

    def test_v4_match_plus_v6_is_unknown_not_pass(self):
        # IPv4 对上了，但还有一条 IPv6 没法验证：不能替它保证没泄漏
        v = bw.assess(self._s(srflx=[PUB, V6]), MASK, 60)
        self.assertEqual(v["state"], "unknown")
        self.assertIn("IPv6", v["title"])

    def test_ipv6_baseline_matches_ipv6_candidate(self):
        v = bw.assess(self._s(srflx=[V6]), "2408:8207:****", 60)
        self.assertEqual(v["state"], "pass")

    def test_mismatch_stale_is_not_leak(self):
        # 基线过期时不一致是正常的，报成泄漏只会教用户忽略告警
        v = bw.assess(self._s(srflx=[OTHER]), MASK, bw.STALE_AFTER + 1)
        self.assertEqual(v["state"], "stale")

    def test_no_baseline_is_unknown_not_pass(self):
        v = bw.assess(self._s(srflx=[PUB]), "", None)
        self.assertEqual(v["state"], "unknown")

    def test_mdns_only_is_pass(self):
        v = bw.assess(self._s(mdns=3), MASK, 60)
        self.assertEqual(v["state"], "pass")

    def test_private_only_is_lan(self):
        v = bw.assess(self._s(host=["192.168.1.5"], private=["192.168.1.5"]), MASK, 60)
        self.assertEqual(v["state"], "lan")

    def test_relay_only_is_relay(self):
        v = bw.assess(self._s(relay=[OTHER]), MASK, 60)
        self.assertEqual(v["state"], "relay")

    def test_nothing_is_empty_not_pass(self):
        v = bw.assess(self._s(), MASK, 60)
        self.assertEqual(v["state"], "empty")

    def test_every_state_has_text(self):
        for s in (self._s(srflx=[PUB]), self._s(srflx=["1.2.3.4"]),
                  self._s(mdns=1), self._s(host=["10.1.1.1"], private=["10.1.1.1"]),
                  self._s(relay=["9.9.9.9"]), self._s()):
            v = bw.assess(s, MASK, 60)
            self.assertTrue(v["title"] and v["detail"], v["state"])


class PersistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old = (bw.STATE_DIR, bw.STATE_FILE)
        bw.STATE_DIR = Path(self.tmp.name) / ".ccclean"
        bw.STATE_FILE = bw.STATE_DIR / "webrtc.json"

    def tearDown(self):
        bw.STATE_DIR, bw.STATE_FILE = self._old
        self.tmp.cleanup()

    def test_roundtrip(self):
        v = bw.save({"candidates": [cand(PUB, "srflx")]}, MASK, 30)
        self.assertEqual(v["state"], "pass")
        rec = bw.load()
        self.assertEqual(rec["assessment"]["state"], "pass")
        self.assertIsNotNone(rec["age"])

    def test_raw_ip_never_hits_disk(self):
        # 落盘的必须是打码地址：完整 IP 写进文件等于这次检测自己制造泄漏
        bw.save({"candidates": [cand(PUB, "srflx"),
                                cand("192.168.1.5")]}, MASK, 30)
        text = bw.STATE_FILE.read_text(encoding="utf-8")
        self.assertNotIn(PUB, text)
        self.assertNotIn("192.168.1.5", text)
        self.assertIn("93.184.*.34", text)

    def test_missing_candidates_raises(self):
        with self.assertRaises(ValueError):
            bw.save({}, MASK, 30)

    def test_file_mode_is_0600(self):
        bw.save({"candidates": []}, MASK, 30)
        self.assertEqual(oct(os.stat(bw.STATE_FILE).st_mode)[-3:], "600")

    def test_candidate_list_is_capped(self):
        many = [cand(f"10.0.0.{i % 250}") for i in range(bw.MAX_CANDIDATES + 50)]
        bw.save({"candidates": many}, MASK, 30)
        self.assertLessEqual(len(bw.load()["summary"]["host"]), bw.MAX_CANDIDATES)

    def test_load_missing_is_empty(self):
        self.assertEqual(bw.load(), {})

    def test_load_corrupt_is_empty(self):
        bw.STATE_DIR.mkdir(parents=True, exist_ok=True)
        bw.STATE_FILE.write_text("{not json", encoding="utf-8")
        self.assertEqual(bw.load(), {})

    def test_clear(self):
        bw.save({"candidates": []}, MASK, 30)
        bw.clear()
        self.assertEqual(bw.load(), {})


class WireTests(unittest.TestCase):
    def test_header_and_qname(self):
        body = doh._wire("example.com", 0x1234)
        qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", body[:12])
        self.assertEqual((qid, flags, qd, an, ns, ar), (0x1234, 0x0100, 1, 0, 0, 0))
        self.assertEqual(body[12:], b"\x07example\x03com\x00\x00\x01\x00\x01")

    def test_short_error_is_short(self):
        self.assertEqual(doh._short(TimeoutError("timed out")), "超时")
        self.assertLessEqual(len(doh._short(OSError("x" * 300))), 60)


class PrefsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _state(self, body):
        f = self.root / "Local State"
        f.write_text(json.dumps(body), encoding="utf-8")
        return f

    def test_chromium_secure(self):
        f = self._state({"dns_over_https": {"mode": "secure",
                                            "templates": "https://dns.google/dns-query"}})
        self.assertEqual(doh._chromium_mode(f),
                         ("secure", "https://dns.google/dns-query", ""))

    def test_chromium_automatic_is_kept(self):
        # automatic 会走 DoH，只是允许回落；不能被折成 off
        f = self._state({"dns_over_https": {"mode": "automatic"}})
        self.assertEqual(doh._chromium_mode(f)[0], "automatic")

    def test_chromium_missing_key(self):
        f = self._state({})
        self.assertEqual(doh._chromium_mode(f), ("", "", ""))

    def test_chromium_corrupt_is_denied_not_unset(self):
        # 文件在、内容坏了：这是「不知道」，不能当成「没设置过」
        f = self.root / "Local State"
        f.write_text("{oops", encoding="utf-8")
        self.assertEqual(doh._chromium_mode(f)[2], "denied")

    def test_chromium_unreadable_is_denied(self):
        f = self.root / "Local State"
        f.write_text("{}", encoding="utf-8")
        real = Path.read_text

        def boom(self_, *a, **kw):
            if self_.name == "Local State":
                raise PermissionError(1, "Operation not permitted")
            return real(self_, *a, **kw)

        Path.read_text = boom
        try:
            self.assertEqual(doh._chromium_mode(f)[2], "denied")
        finally:
            Path.read_text = real

    def test_firefox_mode(self):
        f = self.root / "prefs.js"
        f.write_text('user_pref("network.trr.mode", 3);\n'
                     'user_pref("network.trr.uri", "https://dns.google/dns-query");\n',
                     encoding="utf-8")
        self.assertEqual(doh._firefox_prefs(f), (3, "https://dns.google/dns-query"))

    def test_firefox_missing_key(self):
        f = self.root / "prefs.js"
        f.write_text('user_pref("browser.startup.homepage", "about:blank");\n',
                     encoding="utf-8")
        self.assertEqual(doh._firefox_prefs(f), (-1, ""))

    def test_firefox_unreadable_is_not_missing_key(self):
        self.assertEqual(doh._firefox_prefs(self.root / "prefs.js"), (-2, ""))


class BrowserScanTests(unittest.TestCase):
    """真的走一遍目录遍历，只是把根目录换成临时目录。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._bases = doh._bases
        self._safari = doh._safari_present
        doh._bases = lambda: [self.root]
        doh._safari_present = lambda: False

    def tearDown(self):
        doh._bases = self._bases
        doh._safari_present = self._safari
        self.tmp.cleanup()

    def _chrome(self, mode=None):
        base = self.root / "Google/Chrome"
        base.mkdir(parents=True, exist_ok=True)
        if mode is not None:
            (base / "Local State").write_text(
                json.dumps({"dns_over_https": {"mode": mode}}), encoding="utf-8")
        return base

    def test_chrome_secure_detected(self):
        self._chrome("secure")
        rows = doh.browsers()
        self.assertEqual([r["mode"] for r in rows if r["browser"] == "Chrome"], ["secure"])

    def test_chrome_automatic_detected(self):
        self._chrome("automatic")
        rows = doh.browsers()
        self.assertEqual([r["mode"] for r in rows if r["browser"] == "Chrome"],
                         ["automatic"])

    def test_profile_preferences_is_not_the_source(self):
        # 桌面版的开关在内核读的 Local State 里；只放配置档 Preferences
        # 应当读不到——这条就是防「读错文件」回来的。
        d = self.root / "Google/Chrome/Default"
        d.mkdir(parents=True, exist_ok=True)
        (d / "Preferences").write_text(
            json.dumps({"dns_over_https": {"mode": "secure"}}), encoding="utf-8")
        rows = doh.browsers()
        self.assertEqual([r for r in rows if r["browser"] == "Chrome"], [])

    def test_firefox_detected(self):
        d = self.root / "Firefox/Profiles/abc.default"
        d.mkdir(parents=True, exist_ok=True)
        (d / "prefs.js").write_text('user_pref("network.trr.mode", 2);', encoding="utf-8")
        rows = doh.browsers()
        self.assertEqual([r["mode"] for r in rows if r["browser"] == "Firefox"], ["secure"])

    def test_unreadable_local_state_is_denied_not_off(self):
        # 文件在、但读不出来：这是「不知道」，不能报成「关闭」
        base = self._chrome()
        (base / "Local State").write_text("{}", encoding="utf-8")
        real = Path.read_text

        def boom(self_, *a, **kw):
            if self_.name == "Local State":
                raise PermissionError(1, "Operation not permitted")
            return real(self_, *a, **kw)

        Path.read_text = boom
        try:
            rows = doh.browsers()
        finally:
            Path.read_text = real
        chrome = [r for r in rows if r["browser"] == "Chrome"]
        self.assertEqual(chrome and chrome[0]["mode"], "denied")


class DohAssessTests(unittest.TestCase):
    OK = [{"name": "Cloudflare", "ok": True, "ms": 40, "note": "2 条应答"}]
    DEAD = [{"name": "Cloudflare", "ok": False, "ms": 3000, "note": "超时"}]

    def _b(self, mode, name="Chrome"):
        return [{"browser": name, "mode": mode, "template": "", "source": ""}]

    def test_on_and_reachable_is_pass(self):
        self.assertEqual(doh.assess(self._b("secure"), self.OK)["state"], "pass")

    def test_automatic_is_auto_not_pass(self):
        # automatic 会走 DoH，但不保证一直走；报成「已开启」是替浏览器作保
        v = doh.assess(self._b("automatic"), self.OK)
        self.assertEqual(v["state"], "auto")
        self.assertIn("自动", v["title"])

    def test_firefox_race_is_auto_too(self):
        v = doh.assess(self._b("race", "Firefox"), self.OK)
        self.assertEqual(v["state"], "auto")

    def test_auto_but_blocked_is_fallback(self):
        v = doh.assess(self._b("automatic"), self.DEAD)
        self.assertEqual(v["state"], "fallback")
        self.assertIn("静默", v["detail"])

    def test_secure_with_auto_is_pass_but_mentions_auto(self):
        rows = self._b("secure") + self._b("automatic", "Edge")
        v = doh.assess(rows, self.OK)
        self.assertEqual(v["state"], "pass")
        self.assertIn("自动", v["title"])

    def test_unset_is_unknown_not_off(self):
        # 配置里没有这一项 ≠ 用户关了它
        v = doh.assess(self._b("unset"), self.OK)
        self.assertEqual(v["state"], "unknown")
        self.assertIn("没有安全 DNS 设置", v["title"])

    def test_denied_alongside_readable_is_noted(self):
        rows = self._b("secure") + self._b("denied", "Edge")
        self.assertIn("读不到", doh.assess(rows, self.OK)["detail"])

    def test_on_but_blocked_is_fallback(self):
        v = doh.assess(self._b("secure"), self.DEAD)
        self.assertEqual(v["state"], "fallback")
        self.assertIn("静默", v["detail"])

    def test_off_and_reachable_is_off_not_warning(self):
        # 没开安全 DNS 很常见，真正的泄漏面由 3-4 关卡负责，这里不重复报警
        self.assertEqual(doh.assess(self._b("off"), self.OK)["state"], "off")

    def test_denied_is_unknown_not_off(self):
        v = doh.assess(self._b("denied"), self.OK)
        self.assertEqual(v["state"], "unknown")
        self.assertIn("不知道", v["detail"])

    def test_safari_only_is_unknown(self):
        v = doh.assess(self._b("system", "Safari"), self.OK)
        self.assertEqual(v["state"], "unknown")

    def test_no_browser_is_unknown(self):
        self.assertEqual(doh.assess([], self.OK)["state"], "unknown")

    def test_no_endpoints_still_judges_config(self):
        # 离线扫描时 endpoints 是空列表，不能因为「没测端点」就报 fallback
        self.assertEqual(doh.assess(self._b("secure"), [])["state"], "pass")
        self.assertEqual(doh.assess(self._b("off"), [])["state"], "off")


class WiringTests(unittest.TestCase):
    """产出侧与消费侧各出现一次，否则清单里看得到、关卡里看不见。"""

    def test_scanner_produces_both(self):
        sc = (ROOT / "core/scanner.py").read_text(encoding="utf-8")
        self.assertIn('"net.webrtc_browser"', sc)
        self.assertIn('"net.doh"', sc)

    def test_tower_consumes_both(self):
        tw = (ROOT / "core/tower.py").read_text(encoding="utf-8")
        self.assertIn('"net.webrtc_browser"', tw)
        self.assertIn('"net.doh"', tw)

    def test_app_has_probe_endpoint(self):
        app = (ROOT / "app.py").read_text(encoding="utf-8")
        self.assertIn('"/api/probe/webrtc"', app)
        self.assertIn("browserwebrtc.save(", app)

    def test_frontend_collects_ice(self):
        js = (ROOT / "web/app.js").read_text(encoding="utf-8")
        self.assertIn("RTCPeerConnection", js)
        self.assertIn("iceGatheringState", js)
        self.assertIn("runWebrtcProbe", js)

    def test_probe_button_rendered(self):
        js = (ROOT / "web/app.js").read_text(encoding="utf-8")
        self.assertIn("data-probe=", js)
        tj = (ROOT / "web/tower.js").read_text(encoding="utf-8")
        self.assertIn("data-act-probe", tj)
        self.assertIn("data-settle-action=\"probe\"", tj)

    def test_no_get_user_media(self):
        # 探针不该碰摄像头：碰了就要授权，一次点击变成两次
        js = (ROOT / "web/app.js").read_text(encoding="utf-8")
        self.assertNotIn("getUserMedia(", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
