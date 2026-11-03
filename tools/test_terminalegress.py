#!/usr/bin/env python3
"""登录 shell 里的实际出口。

要固定的判据：

- curl 不读 macOS 的系统代理，所以终端与探测可能从两个地址出去；
- 探测命令是常量，不接受任何输入；shell 里代理变量的**值**不保留；
- 没确认出口时不发请求；地址族不同是「没法比对」，不是「不一致」；
- 完整地址只在内存里比对，返回值只有打码地址。

    python3 tools/test_terminalegress.py
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import compat, deep, terminalegress

TRACE = """fl=123f45
h=api.anthropic.com
ip=203.0.113.9
ts=1793500000.123
loc=JP
colo=NRT
"""

TRACE6 = TRACE.replace("ip=203.0.113.9", "ip=2001:db8::1")


def output(trace: str = TRACE, env: str = "") -> str:
    return trace + "\n" + terminalegress.MARKER + "\n" + env


class ParseTests(unittest.TestCase):
    def test_trace_and_env_are_split(self):
        trace, proxy = terminalegress.parse_output(
            output(env="PATH=/usr/bin\nHTTPS_PROXY=http://127.0.0.1:7890"))
        self.assertEqual(trace["ip"], "203.0.113.9")
        self.assertEqual(trace["loc"], "JP")
        self.assertEqual(trace["colo"], "NRT")
        self.assertTrue(proxy)

    def test_proxy_values_are_not_kept(self):
        _, proxy = terminalegress.parse_output(
            output(env="HTTPS_PROXY=http://user:pass@127.0.0.1:7890"))
        # 返回的是布尔值，值本身没有出口
        self.assertIs(proxy, True)

    def test_upper_and_lower_case_keys_both_count(self):
        for key in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
            _, proxy = terminalegress.parse_output(output(env=f"{key}=x"))
            self.assertTrue(proxy, key)

    def test_no_proxy_alone_is_not_a_proxy_variable(self):
        _, proxy = terminalegress.parse_output(
            output(env="NO_PROXY=localhost,127.0.0.1"))
        self.assertFalse(proxy)

    def test_marker_missing_still_parses_trace(self):
        trace, proxy = terminalegress.parse_output(TRACE)
        self.assertEqual(trace["ip"], "203.0.113.9")
        self.assertFalse(proxy)

    def test_no_trace_means_not_checked(self):
        trace, proxy = terminalegress.parse_output(
            "\n" + terminalegress.MARKER + "\nHTTPS_PROXY=x")
        self.assertIsNone(trace)
        self.assertTrue(proxy)

    def test_garbage_is_not_a_trace(self):
        trace, proxy = terminalegress.parse_output(
            "curl: (28) timed out\n" + terminalegress.MARKER + "\n")
        self.assertIsNone(trace)
        self.assertFalse(proxy)


class ArgvTests(unittest.TestCase):
    def test_flags_per_shell(self):
        self.assertEqual(terminalegress._argv("/bin/zsh", "zsh")[1], "-ilc")
        self.assertEqual(terminalegress._argv("/bin/bash", "bash")[1], "-ilc")
        self.assertEqual(terminalegress._argv("/opt/homebrew/bin/fish", "fish")[1], "-lic")
        self.assertEqual(terminalegress._argv("/bin/sh", "sh")[1], "-lc")
        self.assertEqual(terminalegress._argv("/bin/dash", "dash")[1], "-lc")

    def test_command_is_constant(self):
        script = terminalegress._argv("/bin/zsh", "zsh")[2]
        self.assertIn(terminalegress.TRACE_URL, script)
        self.assertIn(terminalegress.MARKER, script)
        self.assertIn("/usr/bin/curl", script)
        # 没有变量插值，也不读任何外部输入
        self.assertNotIn("$", script)
        self.assertNotIn("${", script)

    def test_unknown_shell_falls_back_to_zsh(self):
        with mock.patch.dict("os.environ", {"SHELL": "/bin/tcsh"}):
            self.assertEqual(terminalegress._shell(), ("/bin/zsh", "zsh"))

    def test_known_shell_is_kept(self):
        with mock.patch.dict("os.environ", {"SHELL": "/bin/bash"}):
            self.assertEqual(terminalegress._shell(), ("/bin/bash", "bash"))


class ProbeTests(unittest.TestCase):
    def run_probe(self, out: str, ip: str = "", mask: str = ""):
        calls = []

        def runner(argv):
            calls.append(argv)
            return out

        with mock.patch.object(compat, "IS_MAC", True):
            result = terminalegress.probe(ip, mask, runner=runner)
        return result, calls

    def test_matching_baseline_is_marked(self):
        out, calls = self.run_probe(output(), "203.0.113.9")
        self.assertTrue(out["checked"])
        self.assertIs(out["match"], True)
        self.assertEqual(out["ipMasked"], "203.0.*.9")
        self.assertTrue(calls[0][0].endswith(("zsh", "bash", "fish")))
        self.assertEqual(calls[0][1], "-ilc")

    def test_different_address_is_a_mismatch(self):
        out, _ = self.run_probe(output(), "198.51.100.7")
        self.assertIs(out["match"], False)

    def test_masked_baseline_is_accepted(self):
        out, _ = self.run_probe(output(), mask="203.0.*.9")
        self.assertIs(out["match"], True)

    def test_no_baseline_leaves_match_unknown(self):
        out, _ = self.run_probe(output(""))
        self.assertIsNone(out["match"])

    def test_address_family_difference_is_not_a_mismatch(self):
        out, _ = self.run_probe(output(TRACE6), ip="203.0.113.9")
        self.assertIsNone(out["match"])
        self.assertEqual(out["ipMasked"], "2001:db8:****")

    def test_full_address_never_leaves_the_probe(self):
        out, _ = self.run_probe(output(), "198.51.100.7")
        self.assertNotIn("203.0.113.9", repr(out))

    def test_proxy_env_flag_is_reported_without_values(self):
        out, _ = self.run_probe(output(env="HTTPS_PROXY=http://u:p@127.0.0.1:7890"))
        self.assertTrue(out["proxyEnv"])
        self.assertNotIn("127.0.0.1:7890", repr(out))
        self.assertNotIn("u:p", repr(out))

    def test_runner_error_does_not_escape(self):
        def boom(_argv):
            raise RuntimeError("nope")

        with mock.patch.object(compat, "IS_MAC", True):
            out = terminalegress.probe("203.0.113.9", runner=boom)
        self.assertFalse(out["checked"])
        self.assertEqual(out["error"], "RuntimeError")

    def test_empty_output_is_not_checked(self):
        out, _ = self.run_probe("", "203.0.113.9")
        self.assertFalse(out["checked"])
        self.assertIn("没有输出", out["error"])

    def test_non_mac_does_not_run_a_shell(self):
        calls = []
        with mock.patch.object(compat, "IS_MAC", False):
            out = terminalegress.probe(runner=lambda argv: calls.append(argv))
        self.assertFalse(out["checked"])
        self.assertIn("macOS", out["error"])
        self.assertEqual(calls, [])


class CheckTests(unittest.TestCase):
    EGRESS = {"available": True, "ip": "203.0.113.9", "ip_masked": "203.0.*.9"}

    def probe(self, **over):
        base = {"checked": True, "ipMasked": "203.0.*.9", "loc": "JP",
                "colo": "NRT", "match": True, "proxyEnv": False,
                "shell": "zsh", "error": ""}
        base.update(over)
        return mock.patch.object(terminalegress, "probe", return_value=base)

    def test_no_egress_means_no_request(self):
        with mock.patch.object(terminalegress, "probe") as probe:
            item = deep.check_terminal_egress({"available": False})
        probe.assert_not_called()
        self.assertEqual(item["id"], "net.terminal_egress")
        self.assertEqual(item["severity"], "info")
        self.assertIn("未检测", item["title"])

    def test_match_is_pass(self):
        with self.probe():
            item = deep.check_terminal_egress(self.EGRESS)
        self.assertEqual(item["severity"], "pass")
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertIn("203.0.*.9 · JP · NRT", ev["终端看到的出口"])
        self.assertEqual(ev["shell 代理变量"], "未设置")

    def test_mismatch_is_high_and_names_the_proxy_variable(self):
        with self.probe(match=False, ipMasked="198.51.*.7", loc="US"):
            item = deep.check_terminal_egress(self.EGRESS)
        self.assertEqual(item["severity"], "high")
        self.assertIn("198.51.*.7", item["detail"])
        self.assertIn("HTTPS_PROXY", item["advice"])
        self.assertIn("203.0.*.9", item["detail"])

    def test_unknown_match_is_info_not_failure(self):
        with self.probe(match=None, ipMasked="2001:db8:****"):
            item = deep.check_terminal_egress(self.EGRESS)
        self.assertEqual(item["severity"], "info")
        self.assertIn("没法直接判断", item["detail"])

    def test_failed_probe_is_info_and_carries_the_error(self):
        with self.probe(checked=False, ipMasked="", error="登录 shell 没有输出"):
            item = deep.check_terminal_egress(self.EGRESS)
        self.assertEqual(item["severity"], "info")
        self.assertIn("登录 shell 没有输出", item["detail"])

    def test_proxy_variable_is_evidence(self):
        with self.probe(proxyEnv=True):
            item = deep.check_terminal_egress(self.EGRESS)
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertEqual(ev["shell 代理变量"], "已设置")

    def test_probe_receives_full_ip_but_the_item_does_not(self):
        seen = {}

        def capture(ip, mask="", runner=None):
            seen["ip"], seen["mask"] = ip, mask
            return {"checked": True, "ipMasked": "203.0.*.9", "loc": "JP",
                    "colo": "NRT", "match": True, "proxyEnv": False,
                    "shell": "zsh", "error": ""}

        with mock.patch.object(terminalegress, "probe", capture):
            item = deep.check_terminal_egress(self.EGRESS)
        self.assertEqual(seen["ip"], "203.0.113.9")
        self.assertEqual(seen["mask"], "203.0.*.9")
        self.assertNotIn("203.0.113.9", repr(item))


if __name__ == "__main__":
    unittest.main(verbosity=2)
