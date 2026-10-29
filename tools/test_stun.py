#!/usr/bin/env python3
"""STUN 探测的纯逻辑测试。

不联网：真发 UDP 的测试在 CI 上不可靠，而「位运算对不对」「什么算泄漏」
恰恰是最需要固定下来的部分。所以响应包用手搓的字节，判定直接调 judge()。

    python3 tools/test_stun.py
"""
import struct
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import stun

MAGIC = b"\x21\x12\xa4\x42"
TXN = bytes(range(1, 13))


def packet(ip: str, xor: bool = True, txn: bytes = TXN, kind: int = 0x0101) -> bytes:
    """拼一条 STUN 响应。"""
    octets = bytearray(int(x) for x in ip.split("."))
    if xor:
        for i in range(4):
            octets[i] ^= MAGIC[i]
    attr_type = 0x0020 if xor else 0x0001
    body = bytes([0x00, 0x01, 0x00, 0x00]) + bytes(octets)   # reserved+family+port+addr
    attr = struct.pack("!HH", attr_type, 8) + body
    return struct.pack("!HH", kind, len(attr)) + MAGIC + txn + attr


class ParseTests(unittest.TestCase):
    def test_xor_mapped_address(self):
        self.assertEqual(stun.parse(packet("5.34.220.136"), TXN), "5.34.220.136")

    def test_high_bytes(self):
        # 高位字节的 XOR 最容易写错：0x21/0x12/0xA4/0x42 四位都要异或
        self.assertEqual(stun.parse(packet("112.97.32.112"), TXN), "112.97.32.112")

    def test_legacy_mapped_address(self):
        self.assertEqual(stun.parse(packet("1.2.3.4", xor=False), TXN), "1.2.3.4")

    def test_wrong_transaction_is_dropped(self):
        # UDP 不保证来源，别的会话的包不能当成自己的
        other = bytes(range(11, 23))
        self.assertIsNone(stun.parse(packet("5.34.220.136", txn=other), TXN))

    def test_non_success_response_is_dropped(self):
        self.assertIsNone(stun.parse(packet("5.34.220.136", kind=0x0111), TXN))

    def test_truncated_packet(self):
        self.assertIsNone(stun.parse(packet("5.34.220.136")[:12], TXN))
        self.assertIsNone(stun.parse(b"", TXN))


class MaskTests(unittest.TestCase):
    def test_wildcard_third_octet(self):
        self.assertTrue(stun.matches_mask("5.34.220.136", "5.34.*.136"))
        self.assertTrue(stun.matches_mask("5.34.7.136", "5.34.*.136"))

    def test_mismatch(self):
        self.assertFalse(stun.matches_mask("5.35.220.136", "5.34.*.136"))
        self.assertFalse(stun.matches_mask("5.34.220.137", "5.34.*.136"))

    def test_garbage(self):
        self.assertFalse(stun.matches_mask("::1", "5.34.*.136"))
        self.assertFalse(stun.matches_mask("", "5.34.*.136"))

    def test_ipv6_prefix_match(self):
        self.assertTrue(stun.matches_mask("2408:8207:8990:5c10::1", "2408:8207:****"))
        self.assertFalse(stun.matches_mask("2408:8208:8990:5c10::1", "2408:8207:****"))

    def test_different_family_never_matches(self):
        # 族不同只能算「没法比对」，绝不能被当成「不一致」
        self.assertFalse(stun.matches_mask("1.2.3.4", "2408:8207:****"))
        self.assertFalse(stun.matches_mask("2408:8207::1", "1.2.*.4"))

    def test_fake_ip_ranges(self):
        self.assertTrue(stun.is_fake("198.18.2.160"))
        self.assertTrue(stun.is_fake("198.19.0.1"))
        self.assertFalse(stun.is_fake("198.17.1.1"))
        self.assertFalse(stun.is_fake("5.34.220.136"))


class JudgeTests(unittest.TestCase):
    """判定必须只报「分裂」。见一个报一个会把人训练成无视通知。"""

    def test_split_is_leak(self):
        leak, why = stun.judge(["5.34.220.136", "112.97.32.112"], "5.34.*.136")
        self.assertTrue(leak, why)

    def test_single_match_is_fine(self):
        self.assertFalse(stun.judge(["5.34.220.136"], "5.34.*.136")[0])

    def test_all_mismatch_is_stale_not_leak(self):
        # 全不符多半是换了节点，基线过期；报出来只会制造误报
        self.assertFalse(stun.judge(["9.9.9.9", "8.8.8.8"], "5.34.*.136")[0])

    def test_no_mask_no_judgement(self):
        self.assertFalse(stun.judge(["5.34.220.136", "112.97.32.112"], "")[0])

    def test_ipv6_mask_is_unusable(self):
        self.assertFalse(stun.judge(["5.34.220.136", "112.97.32.112"], "2408:****")[0])

    def test_empty_foreign(self):
        self.assertFalse(stun.judge([], "5.34.*.136")[0])

    def test_single_foreign_never_leaks(self):
        # 只有一个境外结果时无法区分「分裂」和「基线过期」，宁可不报
        self.assertFalse(stun.judge(["112.97.32.112"], "5.34.*.136")[0])


class StateTests(unittest.TestCase):
    def test_one_foreign_is_unknown_not_pass(self):
        state, why = stun._judge_state(["5.34.220.136"], "5.34.*.136")
        self.assertEqual(state, "unknown", why)

    def test_all_mismatch_is_unknown_not_pass(self):
        state, why = stun._judge_state(["9.9.9.9", "8.8.8.8"], "5.34.*.136")
        self.assertEqual(state, "unknown", why)

    def test_two_matches_is_pass(self):
        state, _ = stun._judge_state(["5.34.1.136", "5.34.2.136"], "5.34.*.136")
        self.assertEqual(state, "pass")


class ProbeContractTests(unittest.TestCase):
    def setUp(self):
        stun.reset_cache()
        self.addCleanup(stun.reset_cache)

    def fake(self, hosts: dict[str, str]):
        calls = []

        def query(host, port, timeout):
            calls.append(host)
            return hosts.get(host)

        return query, calls

    def test_probe_returns_all_keys(self):
        query, _ = self.fake({
            "stun.miwifi.com": "112.97.32.112",
            "stun1.l.google.com": "5.34.220.136",
            "stun.freeswitch.org": "5.34.221.136",
        })
        with mock.patch.object(stun, "query", query):
            r = stun.probe("5.34.*.136", timeout=0.1)
        for k in ("ips", "foreign", "ok", "leak", "state", "mask", "reason"):
            self.assertIn(k, r)
        self.assertIsInstance(r["ips"], list)
        self.assertIsInstance(r["leak"], bool)
        self.assertIn(r["state"], ("leak", "pass", "unknown"))

    def test_single_foreign_response_is_unknown(self):
        query, _ = self.fake({"stun1.l.google.com": "5.34.220.136"})
        with mock.patch.object(stun, "query", query):
            r = stun.probe("5.34.*.136", timeout=0.1)
        self.assertFalse(r["leak"])
        self.assertEqual(r["state"], "unknown")

    def test_no_mask_never_leaks(self):
        query, _ = self.fake({
            "stun.miwifi.com": "112.97.32.112",
            "stun1.l.google.com": "5.34.220.136",
            "stun.freeswitch.org": "112.97.32.112",
        })
        with mock.patch.object(stun, "query", query):
            r = stun.probe("", timeout=0.1)
        self.assertFalse(r["leak"], "没有基线时不该判泄漏")
        self.assertEqual(r["state"], "unknown")

    def test_result_is_cached_for_60_seconds(self):
        query, calls = self.fake({"stun1.l.google.com": "5.34.220.136"})
        with mock.patch.object(stun, "query", query):
            stun.probe("5.34.*.136", timeout=0.1)
            stun.probe("5.34.*.136", timeout=0.1)
        self.assertEqual(len(calls), len(stun.SERVERS),
                         "60 秒内第二次探测不该再发 UDP")

    def test_cache_is_keyed_by_mask(self):
        query, calls = self.fake({"stun1.l.google.com": "5.34.220.136"})
        with mock.patch.object(stun, "query", query):
            stun.probe("5.34.*.136", timeout=0.1)
            stun.probe("9.9.*.9", timeout=0.1)
        self.assertEqual(len(calls), len(stun.SERVERS) * 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
