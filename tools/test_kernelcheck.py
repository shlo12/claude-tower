#!/usr/bin/env python3
"""内核规则核对的判定测试。

全部对着一个假的控制接口跑：真 Clash 内核不参与，也不联网。要固定下来的是
「什么算加载了、什么算没加载」，不是某个人机器上刚好装了什么。

    python3 tools/test_kernelcheck.py
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import kernelcheck


def state(rules, mode="rule", proxies=None, configs=None):
    return {
        "configs": configs if configs is not None else {"mode": mode},
        "rules": {"rules": rules},
        "proxies": {"proxies": proxies if proxies is not None else {
            "Ai+": {"type": "Selector", "now": "香港 01", "all": ["香港 01", "DIRECT"]},
            "香港 01": {"type": "Shadowsocks", "udp": True},
        }},
    }


def rule(kind, payload, proxy="Ai+", **extra):
    item = {"type": kind, "payload": payload, "proxy": proxy}
    item.update(extra)
    return item


PINNED = [rule("DomainSuffix", "claude.ai"), rule("DomainSuffix", "anthropic.com")]
SPECS = [("DOMAIN-SUFFIX", "claude.ai"), ("DOMAIN-SUFFIX", "anthropic.com")]


class AssessTests(unittest.TestCase):
    def test_loaded_rules_pass(self):
        out = kernelcheck.assess(state(PINNED + [rule("Match", "", "DIRECT")]), SPECS, "Ai+")
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["matched"], 2)
        self.assertEqual(out["node"], "香港 01")
        self.assertTrue(out["udp"])

    def test_type_case_and_separators_do_not_matter(self):
        # 内核返回 CamelCase，配置里写 DOMAIN-SUFFIX
        out = kernelcheck.assess(state([rule("DOMAIN-SUFFIX", "Claude.AI")]), SPECS[:1], "Ai+")
        self.assertEqual(out["state"], "ok")

    def test_missing_rule_is_mismatch(self):
        out = kernelcheck.assess(state(PINNED[:1]), SPECS, "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("1 条没加载", out["reason"])
        self.assertEqual(out["missing"], ["DOMAIN-SUFFIX,anthropic.com"])

    def test_rule_after_match_is_dead(self):
        """写在 MATCH 之后等于没写——这是最容易自我感觉良好的那种「已加载」。"""
        rules = [rule("Match", "", "DIRECT")] + PINNED
        out = kernelcheck.assess(state(rules), SPECS, "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("MATCH 之后", out["reason"])

    def test_wrong_policy_is_mismatch(self):
        out = kernelcheck.assess(state([rule("DomainSuffix", "claude.ai", "DIRECT")]),
                                 SPECS[:1], "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("别的策略", out["reason"])

    def test_disabled_rule_counts_as_missing(self):
        out = kernelcheck.assess(
            state([rule("DomainSuffix", "claude.ai", extra={"disabled": True})]),
            SPECS[:1], "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("被禁用", out["missing"][0])

    def test_global_mode_is_not_a_failure(self):
        """全局模式下所有流量都走代理，规则不参与匹配，不能报「没生效」。"""
        out = kernelcheck.assess(state([], mode="global"), SPECS, "Ai+")
        self.assertEqual(out["state"], "global")
        self.assertIn("global", out["reason"])

    def test_group_pointing_at_direct_is_mismatch(self):
        proxies = {"Ai+": {"type": "Selector", "now": "DIRECT", "all": ["DIRECT"]},
                   "DIRECT": {"type": "Direct"}}
        out = kernelcheck.assess(state(PINNED, proxies=proxies), SPECS, "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("不会走代理", out["reason"])

    def test_udp_unsupported_is_reported_but_not_failed(self):
        proxies = {"Ai+": {"type": "Selector", "now": "香港 01", "all": ["香港 01"]},
                   "香港 01": {"type": "Shadowsocks", "udp": False}}
        out = kernelcheck.assess(state(PINNED, proxies=proxies), SPECS, "Ai+")
        self.assertEqual(out["state"], "ok")
        self.assertIs(out["udp"], False)
        self.assertIn("不支持 UDP", kernelcheck.describe(out))

    def test_group_cycle_does_not_hang(self):
        proxies = {"A": {"type": "Selector", "now": "B", "all": ["B"]},
                   "B": {"type": "Selector", "now": "A", "all": ["A"]}}
        rules = [rule("DomainSuffix", d, "A") for d in ("claude.ai", "anthropic.com")]
        out = kernelcheck.assess(state(rules, proxies=proxies), SPECS, "A")
        self.assertEqual(out["state"], "ok")
        self.assertIn(out["node"], ("A", "B"))

    def test_broken_rules_payload_is_unavailable(self):
        out = kernelcheck.assess({"configs": {"mode": "rule"}, "rules": {"rules": "x"}},
                                 SPECS, "Ai+")
        self.assertEqual(out["state"], "unavailable")

    def test_spec_may_carry_its_own_target(self):
        """端口规则故意写成 REJECT 时，不能拿代理组名去套它。"""
        specs = [("DOMAIN-SUFFIX", "claude.ai", "Ai+"), ("DST-PORT", "3478", "REJECT")]
        rules = [rule("DomainSuffix", "claude.ai"),
                 rule("DstPort", "3478", "REJECT"),
                 rule("Match", "", "DIRECT")]
        out = kernelcheck.assess(state(rules), specs, "Ai+")
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["matched"], 2)

    def test_spec_with_own_target_still_catches_the_wrong_one(self):
        specs = [("DST-PORT", "3478", "REJECT")]
        out = kernelcheck.assess(state([rule("DstPort", "3478", "Ai+")]), specs, "Ai+")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("别的策略", out["reason"])

    def test_two_field_spec_falls_back_to_policy(self):
        """老调用点只给 (类型, 载荷)，期望策略仍然是 policy。"""
        out = kernelcheck.assess(state([rule("DstPort", "3478", "DIRECT")]),
                                 [("DST-PORT", "3478")], "Ai+")
        self.assertEqual(out["state"], "mismatch")


class AbsentTests(unittest.TestCase):
    def test_absent_ok_when_nothing_left(self):
        out = kernelcheck.assess(state([rule("Match", "", "DIRECT")]), SPECS, "",
                                 expect="absent")
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["matched"], 2)

    def test_absent_mismatch_when_leftover(self):
        out = kernelcheck.assess(state(PINNED), SPECS, "", expect="absent")
        self.assertEqual(out["state"], "mismatch")
        self.assertIn("还剩", out["reason"])
        self.assertIn("已确认清除", kernelcheck.describe(
            kernelcheck.assess(state([]), SPECS, "", expect="absent")))


class ControllerTests(unittest.TestCase):
    def test_non_loopback_controller_is_rejected(self):
        for raw in ("10.0.0.1:9090", "example.com:9090", "http://8.8.8.8:9090"):
            self.assertIsNone(kernelcheck._tcp_endpoint(raw), raw)

    def test_wildcard_binds_are_rewritten_to_loopback(self):
        self.assertEqual(kernelcheck._tcp_endpoint("0.0.0.0:9090"), ("http", "127.0.0.1", 9090))
        self.assertEqual(kernelcheck._tcp_endpoint("localhost:9090"), ("http", "127.0.0.1", 9090))

    def test_endpoint_with_credentials_is_rejected(self):
        self.assertIsNone(kernelcheck._tcp_endpoint("http://u:p@127.0.0.1:9090"))

    def test_missing_controller_is_unavailable_not_failure(self):
        with tempfile.TemporaryDirectory() as td:
            out = kernelcheck.verify([Path(td)], SPECS, "Ai+")
        self.assertEqual(out["state"], "unavailable")
        self.assertIn("控制接口", out["reason"])


class SocketFallbackTests(unittest.TestCase):
    """服务 socket 只属于 Verge：别的客户端不许借它的内核来回答。"""

    def _config(self, name):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        d = Path(td.name) / name
        d.mkdir()
        (d / "config.yaml").write_text("external-controller: ''\n", encoding="utf-8")
        return d

    def _fake_exists(self, real):
        return lambda p: True if "verge-mihomo" in str(p) else real(p)

    def test_non_verge_dir_does_not_borrow_verge_socket(self):
        d = self._config("com.follow.clash")
        real = kernelcheck.os.path.exists
        with patch.object(kernelcheck.os.path, "exists",
                          side_effect=self._fake_exists(real)):
            with self.assertRaises(kernelcheck.Unavailable):
                kernelcheck.find_controller([d])

    def test_verge_dir_may_use_service_socket(self):
        d = self._config("io.github.clash-verge-rev.clash-verge-rev")
        real = kernelcheck.os.path.exists
        with patch.object(kernelcheck.os.path, "exists",
                          side_effect=self._fake_exists(real)):
            endpoint, _ = kernelcheck.find_controller([d])
        self.assertEqual(endpoint[0], "unix")
        self.assertIn("verge-mihomo.sock", endpoint[1])


class _Handler(BaseHTTPRequestHandler):
    payload: dict = {}

    def do_GET(self):                                   # noqa: N802
        body = self.payload.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class LiveControllerTests(unittest.TestCase):
    """真起一个 HTTP 服务，走完整的 snapshot → assess 链路。"""

    def setUp(self):
        self.payload = {
            "/configs": {"mode": "rule"},
            "/rules": {"rules": PINNED + [rule("Match", "", "DIRECT")]},
            "/proxies": {"proxies": {
                "Ai+": {"type": "Selector", "now": "香港 01", "all": ["香港 01"]},
                "香港 01": {"type": "Shadowsocks", "udp": True},
            }},
        }
        handler = type("H", (_Handler,), {"payload": self.payload})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        (root / "config.yaml").write_text(
            f"mode: rule\nexternal-controller: 127.0.0.1:{self.port}\nsecret: s3cret\n",
            encoding="utf-8")
        self.dirs = [root]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.td.cleanup()

    def test_round_trip_ok(self):
        out = kernelcheck.verify(self.dirs, SPECS, "Ai+")
        self.assertEqual(out["state"], "ok")
        self.assertEqual(out["node"], "香港 01")

    def test_round_trip_detects_missing(self):
        self.payload["/rules"]["rules"] = PINNED[:1]
        out = kernelcheck.verify(self.dirs, SPECS, "Ai+")
        self.assertEqual(out["state"], "mismatch")

    def test_bad_secret_is_reported_as_unavailable(self):
        (Path(self.td.name) / "config.yaml").write_text(
            f"mode: rule\nexternal-controller: 127.0.0.1:{self.port}\nsecret: wrong\n",
            encoding="utf-8")
        # 假服务不校验 secret，这里只确认「连不上/异常」不会变成 mismatch
        out = kernelcheck.verify(self.dirs, SPECS, "Ai+")
        self.assertIn(out["state"], ("ok", "unavailable"))

    def test_dead_port_is_unavailable(self):
        self.server.shutdown()
        self.server.server_close()
        out = kernelcheck.verify(self.dirs, SPECS, "Ai+")
        self.assertEqual(out["state"], "unavailable")


class _UnixHandler(BaseHTTPRequestHandler):
    payload: dict = {}

    def do_GET(self):                                   # noqa: N802
        body = self.payload.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class _UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def get_request(self):
        request, _ = super().get_request()
        return request, ("localhost", 0)


@unittest.skipUnless(hasattr(os, "getuid"), "只有 unix 平台有 unix socket")
class UnixSocketTests(unittest.TestCase):
    """Clash Verge 的控制器是 unix socket，这条路径必须能用。"""

    def test_unix_socket_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            sock = str(Path(td) / "verge.sock")
            handler = type("H", (_UnixHandler,), {"payload": {
                "/configs": {"mode": "rule"},
                "/rules": {"rules": PINNED},
                "/proxies": {"proxies": {"Ai+": {"type": "Selector", "now": "香港 01"},
                                         "香港 01": {"type": "Shadowsocks", "udp": True}}},
            }})
            server = _UnixServer(sock, handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                (Path(td) / "clash-verge.yaml").write_text(
                    f"mode: rule\nexternal-controller-unix: {sock}\nsecret: ''\n",
                    encoding="utf-8")
                out = kernelcheck.verify([Path(td)], SPECS, "Ai+")
            finally:
                server.shutdown()
                server.server_close()
        self.assertEqual(out["state"], "ok", out.get("reason"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
