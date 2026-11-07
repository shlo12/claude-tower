#!/usr/bin/env python3
"""Clash 系客户端的失败回落与 v6 开关。

要固定下来的判据只有两条：

- fallback / url-test / load-balance 组里列了 DIRECT，节点全挂时会退到直连；
- select 组的 DIRECT 只是「可以手动选」，不算回落面；但默认成员（第一个）
  就是 DIRECT 时，规则指向它等于默认直连。

配置解析同时认块式与 flow 式；成员行与 `proxies:` 同缩进也是合法 YAML。

    python3 tools/test_proxyguard.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import compat, deep, proxyguard, tower


# 本机 FlClash 合并结果的结构（值换成示例节点名，不改布局）。
LIVE_LIKE = '''
mixed-port: 7890
ipv6: false
tun:
  enable: true
  stack: system
  auto-route: true
  dns-hijack:
    - "any:53"
proxy-groups:
  - name: "YKKCLOUD"
    type: select
    proxies:
      - "Fallback"
      - "HK"
  - name: "Fallback"
    type: fallback
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    proxies:
      - "HK"
      - "DIRECT"
  - name: "Orphan"
    type: url-test
    proxies:
      - "JP"
      - "DIRECT"
rules:
  - DOMAIN-SUFFIX,claude.ai,YKKCLOUD
  - DOMAIN-SUFFIX,anthropic.com,YKKCLOUD
  - GEOIP,CN,DIRECT
  - MATCH,YKKCLOUD
'''

FLOW = '''
ipv6: true
tun: {enable: true, strict-route: true}
proxy-groups: [{name: A, type: select, proxies: [B, DIRECT]}, {name: B, type: fallback, proxies: [HK, DIRECT]}]
rules: ["DOMAIN-SUFFIX,claude.ai,A", "MATCH,A"]
'''

SAME_INDENT = '''
proxy-groups:
- name: A
  type: select
  proxies:
  - HK
  - B
- name: B
  type: fallback
  proxies:
  - JP
  - DIRECT
rules:
- MATCH,A
'''

CLEAN = '''
ipv6: false
tun:
  enable: true
  strict-route: true
proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "HK"
  - name: "Auto"
    type: url-test
    proxies:
      - "HK"
      - "JP"
rules:
  - MATCH,Proxy
'''


def inspect(text=LIVE_LIKE) -> dict:
    return proxyguard.inspect_text(text, "FlClash", "/tmp/config.yaml")


class ParseTests(unittest.TestCase):
    def test_reads_v6_tun_and_final(self):
        out = inspect()
        self.assertTrue(out["checked"])
        self.assertIs(out["ipv6"], False)
        self.assertIs(out["tun"]["enable"], True)
        self.assertIs(out["tun"]["auto-route"], True)
        self.assertNotIn("strict-route", out["tun"])
        self.assertEqual(out["final"], "YKKCLOUD")

    def test_routes_cover_final_and_claude_rules(self):
        out = inspect()
        kinds = [r["kind"] for r in out["routes"]]
        self.assertEqual(kinds.count("Claude 规则"), 2)
        self.assertIn("最终规则", kinds)
        payloads = [r["payload"] for r in out["routes"] if r["kind"] == "Claude 规则"]
        self.assertEqual(payloads, ["claude.ai", "anthropic.com"])

    def test_failopen_records_auto_groups_and_reachability(self):
        out = inspect()
        by_name = {x["name"]: x for x in out["failopen"]}
        self.assertEqual(set(by_name), {"Fallback", "Orphan"})
        self.assertTrue(by_name["Fallback"]["reachable"])
        self.assertFalse(by_name["Orphan"]["reachable"])
        self.assertEqual(by_name["Fallback"]["type"], "fallback")
        self.assertEqual(by_name["Fallback"]["index"], 1)

    def test_select_member_is_not_a_failopen_group(self):
        # YKKCLOUD 是 select，名单里虽然有 DIRECT 的 Fallback，但它本身不算自动回落
        out = inspect()
        self.assertNotIn("YKKCLOUD", {x["name"] for x in out["failopen"]})

    def test_flow_style_config_is_parsed(self):
        out = inspect(FLOW)
        self.assertIs(out["ipv6"], True)
        self.assertIs(out["tun"]["strict-route"], True)
        self.assertEqual(out["final"], "A")
        self.assertEqual([r["target"] for r in out["eco"]], ["A"])
        # A 的第一个成员是 B，B 的第一个成员是 HK：默认走代理，不是直连
        self.assertEqual(out["defaultDirect"], [])
        self.assertEqual([x["name"] for x in out["failopen"]], ["B"])

    def test_members_may_align_with_the_key(self):
        out = inspect(SAME_INDENT)
        self.assertEqual([x["name"] for x in out["failopen"]], ["B"])
        self.assertEqual(out["final"], "A")
        self.assertFalse(out["defaultDirect"])

    def test_quoted_member_name_with_comma_still_matches(self):
        text = '''
proxy-groups:
  - name: "A, B"
    type: fallback
    proxies:
      - HK
      - DIRECT
rules:
  - DOMAIN-SUFFIX,claude.ai,'A, B'
  - MATCH,'A, B'
'''
        out = inspect(text)
        self.assertEqual(out["final"], "A, B")
        self.assertEqual([x["name"] for x in out["failopen"]], ["A, B"])
        self.assertEqual(out["eco"][0]["target"], "A, B")

    def test_commented_group_is_ignored(self):
        text = LIVE_LIKE.replace(
            '  - name: "Orphan"',
            '  # - name: "Evil"\n  #   type: fallback\n  #   proxies:\n'
            '  #     - DIRECT\n  - name: "Orphan"')
        out = inspect(text)
        self.assertNotIn("Evil", {x["name"] for x in out["failopen"]})

    def test_empty_config_is_not_a_pass(self):
        out = inspect("")
        self.assertFalse(out["checked"])
        self.assertIn("没读到", out["note"])
        self.assertEqual(out["failopen"], [])

    def test_config_values_do_not_leak(self):
        text = LIVE_LIKE.replace("mixed-port: 7890",
                                 "mixed-port: 7890\npassword: \"sekrit-token\"")
        out = inspect(text)
        self.assertNotIn("sekrit-token", json.dumps(out, ensure_ascii=False))

    def test_config_path_is_home_relative(self):
        path = Path(compat.HOME) / "Library/Application Support/FlClash/config.yaml"
        out = proxyguard.inspect_text(LIVE_LIKE, "FlClash", str(path))
        self.assertEqual(out["config"],
                         "~/Library/Application Support/FlClash/config.yaml")


class FallbackCheckTests(unittest.TestCase):
    def test_unchecked_is_info(self):
        item = deep.check_proxy_fallback({"checked": False, "note": "没找到配置"})
        self.assertEqual(item["id"], "net.proxy_fallback")
        self.assertEqual(item["severity"], "info")
        self.assertIn("没找到配置", item["detail"])

    def test_live_like_config_is_medium_with_strict_route_tip(self):
        item = deep.check_proxy_fallback(inspect())
        self.assertEqual(item["severity"], "medium")
        self.assertIn("Fallback", item["title"])
        labels = [e["label"] for e in item["evidence"]]
        self.assertIn("最终规则", labels)
        self.assertIn("含 DIRECT 的自动组", labels)
        self.assertIn("严格路由", labels)
        self.assertIn("REJECT", item["advice"])
        self.assertIn("strict-route", item["advice"])

    def test_match_to_direct_is_high(self):
        item = deep.check_proxy_fallback(inspect(LIVE_LIKE.replace(
            "MATCH,YKKCLOUD", "MATCH,DIRECT")))
        self.assertEqual(item["severity"], "high")
        self.assertIn("最终规则直接放行", item["title"])
        self.assertIn("真实地址", item["detail"])

    def test_claude_rule_to_direct_default_member_is_not_confirmed_direct(self):
        text = LIVE_LIKE.replace(
            '  - name: "YKKCLOUD"\n    type: select\n    proxies:\n'
            '      - "Fallback"\n      - "HK"',
            '  - name: "YKKCLOUD"\n    type: select\n    proxies:\n'
            '      - "DIRECT"\n      - "HK"').replace("MATCH,YKKCLOUD", "MATCH,HK")
        item = deep.check_proxy_fallback(inspect(text))
        self.assertNotEqual(item["severity"], "high")
        self.assertEqual(inspect(text)["defaultDirect"], [])

    def test_unreachable_group_is_only_low(self):
        text = (LIVE_LIKE.replace("MATCH,YKKCLOUD", "MATCH,HK")
                .replace(",claude.ai,YKKCLOUD", ",claude.ai,HK")
                .replace(",anthropic.com,YKKCLOUD", ",anthropic.com,HK"))
        item = deep.check_proxy_fallback(inspect(text))
        self.assertEqual(item["severity"], "low")
        self.assertIn("没有规则指向它", item["title"])
        self.assertIn("Orphan", item["title"])
        self.assertIn("Fallback", item["title"])

    def test_clean_config_is_pass(self):
        item = deep.check_proxy_fallback(inspect(CLEAN))
        self.assertEqual(item["severity"], "pass")
        self.assertIn("不会退到直连", item["title"])
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertEqual(ev["严格路由"], "已开启")
        self.assertNotIn("strict-route", item["advice"])

    def test_strict_route_tip_needs_tun(self):
        text = CLEAN.replace("  strict-route: true", "").replace(
            "tun:\n  enable: true", "tun:\n  enable: false")
        item = deep.check_proxy_fallback(inspect(text))
        self.assertEqual(item["severity"], "pass")
        self.assertNotIn("strict-route", item["detail"] + item["advice"])
        self.assertNotIn("严格路由", [e["label"] for e in item["evidence"]])


class DriftCheckTests(unittest.TestCase):
    """Claude 的出口会不会被自动组自己切走。

    和回落检测分属两件事：那条问「节点全挂时退到哪」，这条问「平时会不会换」。
    实测踩过的情形是回落全绿、规则全命中，出口却由 url-test 决定。
    """

    AUTO = '''
proxy-groups:
  - name: "自动选择"
    type: url-test
    proxies: ["HK", "US"]
  - name: "全球代理"
    type: select
    proxies: ["自动选择", "HK"]
rules:
  - DOMAIN-SUFFIX,claude.ai,自动选择
  - DOMAIN-SUFFIX,anthropic.com,自动选择
  - MATCH,全球代理
'''

    PINNED = '''
proxy-groups:
  - name: "自动选择"
    type: url-test
    proxies: ["HK", "US"]
  - name: "CLAUDE"
    type: select
    proxies: ["US", "HK"]
rules:
  - DOMAIN-SUFFIX,claude.ai,CLAUDE
  - DOMAIN-SUFFIX,anthropic.com,CLAUDE
  - MATCH,自动选择
'''

    def test_unchecked_is_info(self):
        item = deep.check_proxy_drift({"checked": False, "note": "没找到配置"})
        self.assertEqual(item["id"], "net.proxy_drift")
        self.assertEqual(item["severity"], "info")
        self.assertIn("没找到配置", item["detail"])

    def test_claude_rule_on_url_test_group_is_medium(self):
        item = deep.check_proxy_drift(inspect(self.AUTO))
        self.assertEqual(item["severity"], "medium")
        self.assertIn("自动测速组", item["title"])
        self.assertIn("自动选择", item["title"])
        self.assertIn("select", item["advice"])
        labels = [e["label"] for e in item["evidence"]]
        self.assertIn("会自己换节点的组", labels)

    def test_claude_rule_on_select_group_passes(self):
        item = deep.check_proxy_drift(inspect(self.PINNED))
        # Claude 走的是 select 组，只有 MATCH 那条还在自动组上。
        self.assertEqual(item["severity"], "low")
        self.assertIn("出口由自动测速组决定", item["title"])
        self.assertIn("Claude 专用规则", item["detail"])

    def test_no_claude_rule_and_clean_route_passes(self):
        item = deep.check_proxy_drift(inspect(CLEAN))
        self.assertEqual(item["severity"], "pass")
        self.assertIn("不会被自动切走", item["title"])
        self.assertNotIn("会自己换节点的组", [e["label"] for e in item["evidence"]])

    def test_nested_select_into_auto_group_is_caught(self):
        # select 组里套了一个 fallback 组：用户以为固定了，其实没有。
        item = deep.check_proxy_drift(inspect())
        self.assertEqual(item["severity"], "medium")
        self.assertIn("Fallback", item["title"])

    def test_select_group_is_never_drift(self):
        text = self.AUTO.replace("type: url-test", "type: select")
        g = proxyguard.inspect_text(text, "FlClash")
        self.assertEqual(g["drift"], [])

    def test_drift_is_deduped_per_route(self):
        g = proxyguard.inspect_text(self.AUTO, "FlClash")
        keys = [(d["kind"], d["group"]) for d in g["drift"]]
        self.assertEqual(len(keys), len(set(keys)))


class Ipv6EvidenceTests(unittest.TestCase):
    def exposure(self):
        return mock.patch.object(compat, "ipv6_exposure",
                                 return_value={"sample": [], "has_default_v6_route": False})

    def test_client_switch_is_evidence_even_without_system_v6(self):
        with self.exposure():
            item = deep.check_ipv6(inspect())
        self.assertEqual(item["severity"], "pass")
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertEqual(ev["客户端 v6"], "已关闭（ipv6: false）")

    def test_client_v6_on_but_no_system_exit_is_not_a_leak(self):
        with self.exposure():
            item = deep.check_ipv6(inspect(FLOW))
        self.assertIn("不构成泄漏面", item["detail"])

    def test_unreadable_config_says_unread(self):
        with self.exposure():
            item = deep.check_ipv6({"checked": False})
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertEqual(ev["客户端 v6"], "未读到")

    def test_no_guard_reads_the_config_once(self):
        with self.exposure(), \
                mock.patch.object(proxyguard, "inspect", return_value=inspect()) as ins:
            item = deep.check_ipv6()
        ins.assert_called_once()
        ev = {e["label"]: e["value"] for e in item["evidence"]}
        self.assertEqual(ev["客户端 v6"], "已关闭（ipv6: false）")


def stub(*_a, **_kw):
    return {"id": "stub", "category": "network", "title": "stub",
            "severity": "pass", "detail": "", "evidence": [], "advice": "",
            "fix": None, "tags": []}


class WiringTests(unittest.TestCase):
    SRC = Path(__file__).resolve().parent.parent

    def test_both_checks_run_in_a_deep_scan(self):
        names = [
            "check_marker_signature", "check_rhythm", "check_browser",
            "check_permissions", "check_pinned", "check_routing",
            "check_transport", "check_proxy_dns", "check_mitm", "check_ipv6",
            "check_versions",
        ]
        patches = {n: stub for n in names}
        guard = inspect()
        term = {"checked": True, "ipMasked": "38.190.*.188", "loc": "US",
                "colo": "SLC", "match": True, "proxyEnv": False,
                "shell": "zsh", "error": ""}
        with mock.patch.multiple(deep, **patches), \
                mock.patch.object(deep.telemetry, "inspect", stub), \
                mock.patch.object(deep, "check_dnsbl", stub), \
                mock.patch.object(proxyguard, "inspect", return_value=guard), \
                mock.patch.object(deep.terminalegress, "probe", return_value=term):
            items = deep.check_deep({"available": True, "ip": "38.190.1.188",
                                     "ip_masked": "38.190.*.188"})
        ids = {i["id"] for i in items}
        self.assertIn("net.proxy_fallback", ids)
        self.assertIn("net.terminal_egress", ids)

    def test_card_escalates_on_the_worse_extra(self):
        out = {"sev": "pass", "value": "v", "detail": "d",
               "evidence": [{"label": "orig", "value": "x"}], "advice": ""}
        idx = {
            "net.proxy_fallback": {
                "severity": "medium", "title": "自动回落组里有 DIRECT（Fallback）",
                "detail": "回落面", "advice": "换成 REJECT",
                "evidence": [{"label": "自动组", "value": "Fallback"}]},
            "net.terminal_egress": {
                "severity": "pass", "title": "终端出口与检测一致",
                "detail": "一致", "advice": "",
                "evidence": [{"label": "终端", "value": "38.190.*.188"}]},
        }
        merged = tower._merge_proxy_extras(dict(out), idx)
        self.assertEqual(merged["sev"], "medium")
        self.assertEqual(merged["value"], "自动回落组里有 DIRECT（Fallback）")
        self.assertIn("d", merged["detail"])
        self.assertIn("回落面", merged["detail"])
        self.assertEqual(merged["advice"], "换成 REJECT")
        labels = [e["label"] for e in merged["evidence"]]
        self.assertEqual(labels[0], "orig")
        self.assertEqual(labels[1], "自动组")
        self.assertEqual(labels[2], "终端")

    def test_evidence_keeps_the_cards_own_first(self):
        out = {"sev": "medium", "value": "v", "detail": "d", "advice": "",
               "evidence": [{"label": f"own{i}", "value": "x"} for i in range(6)]}
        idx = {
            "net.proxy_fallback": {
                "severity": "high", "title": "t1", "detail": "",
                "advice": "", "evidence": [{"label": f"fb{i}", "value": "x"}
                                           for i in range(4)]},
            "net.terminal_egress": {
                "severity": "pass", "title": "t2", "detail": "",
                "advice": "", "evidence": [{"label": f"tm{i}", "value": "x"}
                                           for i in range(4)]},
        }
        merged = tower._merge_proxy_extras(dict(out), idx)
        labels = [e["label"] for e in merged["evidence"]]
        self.assertEqual(len(labels), 8)
        self.assertEqual(labels[:6], [f"own{i}" for i in range(6)])
        # 更严重的那条先补
        self.assertEqual(labels[6:8], ["fb0", "fb1"])

    def test_card_keeps_its_own_wording_when_extras_pass(self):
        out = {"sev": "high", "value": "内核泄漏", "detail": "d",
               "evidence": [], "advice": "a"}
        idx = {"net.proxy_fallback": {"severity": "pass", "title": "ok",
                                      "detail": "", "evidence": [],
                                      "advice": ""}}
        merged = tower._merge_proxy_extras(dict(out), idx)
        self.assertEqual(merged["sev"], "high")
        self.assertEqual(merged["value"], "内核泄漏")
        self.assertEqual(merged["detail"], "d")
        self.assertEqual(merged["advice"], "a")

    def test_worst_extra_wins(self):
        out = {"sev": "pass", "value": "v", "detail": "", "evidence": [],
               "advice": ""}
        idx = {
            "net.proxy_fallback": {"severity": "high", "title": "high",
                                   "detail": "h", "evidence": [], "advice": ""},
            "net.terminal_egress": {"severity": "medium", "title": "med",
                                    "detail": "m", "evidence": [], "advice": ""},
        }
        merged = tower._merge_proxy_extras(dict(out), idx)
        self.assertEqual(merged["value"], "high")

    def test_ids_are_declared_in_tower(self):
        # 断成员而不是断整行：这一条曾经因为「多了一个 id」就失败，
        # 而真正要保证的是「这三个 id 都在 _PROXY_EXTRAS 里，别漏读」。
        tw = (self.SRC / "core/tower.py").read_text(encoding="utf-8")
        line = next((x for x in tw.splitlines() if x.startswith("_PROXY_EXTRAS")), "")
        for iid in ("net.proxy_fallback", "net.proxy_drift", "net.terminal_egress"):
            self.assertIn(f'"{iid}"', line)

    def test_module_only_reads(self):
        src = (self.SRC / "core/proxyguard.py").read_text(encoding="utf-8")
        for bad in ("write_text(", "unlink(", "os.replace(", "open("):
            self.assertNotIn(bad, src, bad)

    def test_inspect_without_a_running_client_is_unchecked(self):
        out = proxyguard.inspect(commands=[], specs=[])
        self.assertFalse(out["checked"])
        self.assertIn("没找到", out["note"])

    def test_inspect_reads_only_active_clients(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.yaml").write_text(LIVE_LIKE, encoding="utf-8")
            specs = [(str(root), "FlClash", ("myclient",), ())]
            off = proxyguard.inspect(commands=["/usr/sbin/other"], specs=specs)
            self.assertFalse(off["checked"])
            on = proxyguard.inspect(
                commands=["/Applications/MyClient.app/Contents/MacOS/myclient"],
                specs=specs)
            self.assertTrue(on["checked"])
            self.assertEqual(on["client"], "FlClash")
            self.assertIs(on["ipv6"], False)

    def test_confirmed_egress_flow_reaches_the_card(self):
        dns = {"id": "net.proxy_dns", "severity": "info", "title": "境外解析",
               "dns": {"system": ["1.1.1.1"], "systemDomestic": [],
                       "clients": [], "domesticDestination": [],
                       "domesticNode": [], "domesticProxied": [],
                       "domesticDirect": [], "domesticPolicy": [],
                       "note": "", "resolver": {}}}
        fb = deep.check_proxy_fallback(inspect())
        tm = {"id": "net.terminal_egress", "severity": "high",
              "title": "终端里的出口与检测出口不同",
              "detail": "终端直连", "advice": "export HTTPS_PROXY",
              "evidence": [{"label": "shell 代理变量", "value": "未设置"}]}
        scan = {"items": [
            {"id": "net.proxy_path", "severity": "pass", "title": "TUN", "evidence": []},
            dns, fb, tm,
        ]}
        out = tower._probe_proxy(scan, {})
        self.assertEqual(out["sev"], "high")
        self.assertEqual(out["value"], "终端里的出口与检测出口不同")
        self.assertIn("shell 代理变量", [e["label"] for e in out["evidence"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
