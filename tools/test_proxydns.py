#!/usr/bin/env python3
"""代理内核 DNS：解析、归属判定、只认运行中的客户端、关卡接线。

TUN 打开后，真正解析域名的是客户端内核的 nameserver，macOS 的 DNS 设置
会被绕过。这里固定三件事：

- 三组名单必须分开：解析域名 / 启动解析 / 节点域名；
- 国内解析器既认 IP 也认 DoH 域名，但 `system` 跟随系统 DNS；
- 没在运行的客户端留下的旧配置不能替用户「背锅」，helper/service 进程
  也不能被当成客户端。

    python3 tools/test_proxydns.py
"""
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import compat, deep, proxydns, tower


# 从本机 FlClash 生成出来的配置里摘的 dns 段（原样保留引号和顺序）。
FLCLASH = '''
mixed-port: 7890
mode: "rule"
dns:
  enable: true
  nameserver:
    - "8.8.8.8"
    - "https://doh.pub/dns-query"
    - "https://dns.alidns.com/dns-query"
  fallback: []
  enhanced-mode: "fake-ip"
  fake-ip-range: "198.18.0.1/16"
  default-nameserver:
    - "system"
    - "223.6.6.6"
    - "8.8.8.8"
  nameserver-policy: null
  proxy-server-nameserver:
    - "https://dns.alidns.com/dns-query"
    - "tls://223.5.5.5"
    - "223.5.5.5"
tun:
  enable: true
  dns-hijack:
    - "any:53"
'''


def report(**over) -> dict:
    base = {
        "system": ["8.8.8.8"],
        "systemDomestic": [],
        "clients": [{
            "name": "FlClash", "mode": "fake-ip", "config": "/tmp/config.yaml",
            "destination": over.get("domesticDestination") or ["8.8.8.8"],
            "bootstrap": [],
            "node": over.get("domesticNode") or [],
        }],
        "domesticDestination": [],
        "domesticNode": [],
        "note": "",
    }
    base.update(over)
    return base


def scan(*items) -> dict:
    return {"items": list(items)}


BASE_ITEMS = (
    {"id": "net.proxy_path", "severity": "pass",
     "title": "代理链路已建立（TUN）", "evidence": []},
    {"id": "net.proxy", "severity": "info", "title": "系统代理已启用"},
)


class ParseTests(unittest.TestCase):
    def test_block_lists_are_split_into_three_roles(self):
        client = proxydns.inspect_text(FLCLASH, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["mode"], "fake-ip")
        self.assertEqual(client["destination"], [
            "8.8.8.8",
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query",
        ])
        self.assertEqual(client["domesticDestination"], [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query",
        ])
        # 节点域名用国内解析是正常且必要的，不能算泄漏
        self.assertEqual(client["domesticNode"], [
            "https://dns.alidns.com/dns-query",
            "tls://223.5.5.5",
            "223.5.5.5",
        ])
        self.assertEqual(client["domesticBootstrap"], ["223.6.6.6"])

    def test_flow_lists_and_comments(self):
        text = (
            "dns:\n"
            "  nameserver: [1.1.1.1, https://doh.pub/dns-query]  # 两个\n"
            "  fallback: []\n"
            "  proxy-server-nameserver: [https://dns.google/dns-query]\n"
            "rules:\n"
            "  - MATCH,DIRECT\n"
        )
        client = proxydns.inspect_text(text, "x", system_dns=["8.8.8.8"])
        self.assertEqual(client["destination"], ["1.1.1.1", "https://doh.pub/dns-query"])
        self.assertEqual(client["node"], ["https://dns.google/dns-query"])
        self.assertEqual(client["domesticDestination"], ["https://doh.pub/dns-query"])

    def test_nested_policy_lists_do_not_leak_into_nameserver(self):
        text = (
            "dns:\n"
            "  nameserver:\n"
            "    - 1.1.1.1\n"
            "  nameserver-policy:\n"
            "    \"geosite:cn\":\n"
            "      - 223.5.5.5\n"
            "    \"geosite:google\":\n"
            "      - 8.8.8.8\n"
            "  proxy-server-nameserver:\n"
            "    - 223.5.5.5\n"
        )
        client = proxydns.inspect_text(text, "x", system_dns=["8.8.8.8"])
        self.assertEqual(client["destination"], ["1.1.1.1"])
        self.assertEqual(client["domesticDestination"], [])
        self.assertEqual(client["node"], ["223.5.5.5"])

    def test_block_without_dns_returns_none(self):
        self.assertIsNone(proxydns.inspect_text("mode: rule\n", "x"))


class ClassifyTests(unittest.TestCase):
    def test_known_domestic_resolvers(self):
        for value in ("223.5.5.5", "114.114.114.114", "119.29.29.29",
                      "https://doh.pub/dns-query", "https://dns.alidns.com/dns-query",
                      "tls://223.5.5.5", "doh.pub."):
            self.assertTrue(proxydns.is_domestic(value), value)

    def test_foreign_and_lookalike_hosts_are_not_domestic(self):
        for value in ("8.8.8.8", "1.1.1.1", "https://dns.google/dns-query",
                      "https://cloudflare-dns.com/dns-query",
                      "https://doh.pub.evil.com/dns-query", "doh.pub.example"):
            self.assertFalse(proxydns.is_domestic(value), value)

    def test_system_follows_system_dns(self):
        self.assertTrue(proxydns.is_domestic("system", ["223.5.5.5"]))
        self.assertFalse(proxydns.is_domestic("system", ["8.8.8.8"]))
        self.assertFalse(proxydns.is_domestic("dhcp://en0", ["8.8.8.8"]))


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "config.yaml").write_text(FLCLASH, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def collect(self, commands):
        return proxydns.collect(
            system_dns=["8.8.8.8"], commands=commands,
            specs=[(str(self.root), "FlClash", ("flclash",), ())])

    def test_running_client_is_read(self):
        rep = self.collect(["/Applications/FlClash.app/Contents/MacOS/FlClashCore"])
        self.assertEqual(len(rep["clients"]), 1)
        self.assertEqual(rep["domesticDestination"], [
            "https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"])
        self.assertEqual(rep["note"], "")

    def test_stale_config_without_running_client_is_ignored(self):
        rep = self.collect(["/Applications/Other.app/Contents/MacOS/Other"])
        self.assertEqual(rep["clients"], [])
        self.assertIn("没找到运行中", rep["note"])

    def test_helper_and_service_processes_are_not_clients(self):
        for cmd in ("/Library/PrivilegedHelperTools/party.mihomo.helper",
                    "/Library/PrivilegedHelperTools/clash-verge-service",
                    "FlClashWidgetExtension"):
            self.assertEqual(self.collect([cmd])["clients"], [], cmd)


class DeepItemTests(unittest.TestCase):
    def test_tunneled_domestic_destination_is_medium(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"],
                     domesticNode=["223.5.5.5"])
        item = deep.check_proxy_dns(state={"tunneled": True}, report=rep)
        self.assertEqual(item["id"], "net.proxy_dns")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("doh.pub", item["title"])
        self.assertIn("节点域名", item["detail"])
        self.assertIn("dns", item)

    def test_configured_but_not_tunneled_is_info(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"])
        item = deep.check_proxy_dns(state={"tunneled": False}, report=rep)
        self.assertEqual(item["severity"], "info")
        self.assertIn("没有接管", item["detail"])

    def test_clean_proxy_is_pass(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report())
        self.assertEqual(item["severity"], "pass")

    def test_unreadable_proxy_is_info_not_pass(self):
        item = deep.check_proxy_dns(
            state={"tunneled": True},
            report=report(clients=[], note="没找到运行中的客户端配置，读不到它的 DNS 名单"))
        self.assertEqual(item["severity"], "info")
        self.assertIn("不代表没有国内解析器", item["detail"])

    def test_no_config_mentions_system_dns(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report())
        labels = [e["label"] for e in item["evidence"]]
        self.assertIn("系统 DNS", labels)


class TowerProbeTests(unittest.TestCase):
    def probe(self, rep, route, pitem=None):
        item = pitem or deep.check_proxy_dns(
            state={"tunneled": True}, report=rep)
        items = [*BASE_ITEMS, item, route]
        return tower._probe_proxy(scan(*items), {})

    def test_proxy_only_leak_names_the_kernel(self):
        out = self.probe(
            report(domesticDestination=["https://doh.pub/dns-query"]),
            {"id": "net.dns_route", "title": "DNS 已被代理接管"})
        self.assertEqual(out["sev"], "medium")
        self.assertTrue(out["value"].startswith("代理内核 DNS"))
        self.assertNotIn("系统 DNS 与", out["value"])
        self.assertIn("nameserver", out["advice"])

    def test_system_leak_still_wins_when_dns_is_not_hijacked(self):
        out = self.probe(
            report(system=["223.5.5.5"], systemDomestic=["223.5.5.5"]),
            {"id": "net.dns_route", "title": "DNS 解析到真实地址，且没有代理链路"})
        self.assertEqual(out["sev"], "medium")
        self.assertTrue(out["value"].startswith("系统 DNS"))
        self.assertIn("223.5.5.5", out["value"])

    def test_hijacked_system_dns_is_not_reported_as_a_leak(self):
        out = self.probe(
            report(system=["223.5.5.5"], systemDomestic=["223.5.5.5"]),
            {"id": "net.dns_route", "title": "DNS 已被代理接管"})
        self.assertNotEqual(out["sev"], "medium")
        self.assertIn("不生效", out["value"])

    def test_both_paths_are_named(self):
        out = self.probe(
            report(system=["223.5.5.5"], systemDomestic=["223.5.5.5"],
                   domesticDestination=["https://dns.alidns.com/dns-query"]),
            {"id": "net.dns_route", "title": "DNS 解析到真实地址，且没有代理链路"})
        self.assertEqual(out["sev"], "medium")
        self.assertIn("系统 DNS 与代理 DNS", out["value"])
        self.assertIn("alidns", out["value"])

    def test_proxy_config_without_tunnel_is_info(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"])
        item = deep.check_proxy_dns(state={"tunneled": False}, report=rep)
        out = self.probe(rep, {"id": "net.dns_route", "title": "DNS 已被代理接管"},
                         pitem=item)
        self.assertNotEqual(out["sev"], "medium")
        self.assertIn("没接管流量", out["value"])

    def test_fallback_without_deep_item_still_reads_system_dns(self):
        out = tower._probe_proxy(scan(
            *BASE_ITEMS,
            {"id": "net.dns", "severity": "info", "title": "DNS：223.5.5.5",
             "evidence": [{"label": "nameserver", "value": "223.5.5.5"}]},
            {"id": "net.dns_route", "title": "DNS 解析到真实地址，且没有代理链路"},
        ), {})
        self.assertEqual(out["sev"], "medium")
        self.assertIn("223.5.5.5", out["value"])


class WiringTests(unittest.TestCase):
    SRC = Path(__file__).resolve().parent.parent

    def test_item_is_produced_and_consumed(self):
        dp = (self.SRC / "core/deep.py").read_text(encoding="utf-8")
        tw = (self.SRC / "core/tower.py").read_text(encoding="utf-8")
        self.assertIn("check_proxy_dns,", dp)
        self.assertIn('"net.proxy_dns"', dp)
        self.assertIn('"net.proxy_dns"', tw)
        self.assertIn('pd.get("systemDomestic")', tw)
        self.assertIn('pd.get("domesticDestination")', tw)

    def test_module_only_reads(self):
        src = (self.SRC / "core/proxydns.py").read_text(encoding="utf-8")
        for bad in ("write_text(", "open(", "unlink(", "os.replace("):
            self.assertNotIn(bad, src, bad)

    def test_one_shared_domestic_list(self):
        # 关卡里的旧常量已经移除，避免两份名单各自漂移
        tw = (self.SRC / "core/tower.py").read_text(encoding="utf-8")
        self.assertNotIn("CN_DNS = (", tw)
        self.assertIn("proxydns.CN_DNS_IPS", tw)

    def test_flclash_pid_like_config_matches_code(self):
        # 防止解析器和真实客户端格式脱节：用本机摘下来的格式做一次正命中
        client = proxydns.inspect_text(FLCLASH, "FlClash", system_dns=["8.8.8.8"])
        self.assertTrue(client["domesticDestination"])
        self.assertTrue(re.search(r"doh\.pub", " ".join(client["domesticDestination"])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
