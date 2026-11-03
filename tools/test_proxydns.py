#!/usr/bin/env python3
"""代理内核 DNS：解析、归属判定、只认运行中的客户端、关卡接线。

TUN 打开后，真正解析域名的是客户端内核的 nameserver，macOS 的 DNS 设置
会被绕过。这里固定四件事：

- 四组名单必须分开：解析域名 / 国内域名 / 启动解析 / 节点域名；
- `nameserver-policy` 只影响国内域名，不能算进代理域名的泄漏面；
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
from core import compat, deep, proxydns, resolveregress, tower


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
            "policy": over.get("policy") or [],
        }],
        "domesticDestination": [],
        "domesticNode": [],
        "domesticPolicy": [],
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

    def test_proxied_and_direct_nameservers_are_split(self):
        text = (
            "dns:\n"
            "  nameserver:\n"
            "    - https://1.1.1.1/dns-query#RULES\n"
            "  direct-nameserver:\n"
            "    - https://doh.pub/dns-query\n"
            "    - 223.5.5.5\n"
        )
        client = proxydns.inspect_text(text, "x", system_dns=["223.5.5.5"])
        self.assertEqual(client["domesticDestination"], [
            "https://doh.pub/dns-query", "223.5.5.5"])
        # 代理域名只走境外 DoH；国内的只用于直连域名
        self.assertEqual(client["domesticProxied"], [])
        self.assertEqual(client["domesticDirect"], [
            "https://doh.pub/dns-query", "223.5.5.5"])

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

    def test_block_policy_pairs_selector_with_server(self):
        text = (
            "dns:\n"
            "  nameserver:\n"
            "    - 1.1.1.1\n"
            "  nameserver-policy:\n"
            "    \"geosite:cn\":\n"
            "      - https://doh.pub/dns-query\n"
            "    \"geosite:google\":\n"
            "      - 8.8.8.8\n"
            "  proxy-server-nameserver:\n"
            "    - 223.5.5.5\n"
        )
        client = proxydns.inspect_text(text, "x", system_dns=["8.8.8.8"])
        self.assertEqual(client["policy"], [
            {"selector": "geosite:cn", "server": "https://doh.pub/dns-query"},
            {"selector": "geosite:google", "server": "8.8.8.8"},
        ])
        # 只把国内域名交给国内解析器，代理域名的名单不受影响
        self.assertEqual(client["domesticPolicy"], ["https://doh.pub/dns-query"])
        self.assertEqual(client["destination"], ["1.1.1.1"])
        self.assertEqual(client["domesticProxied"], [])

    def test_flow_policy_is_parsed(self):
        text = (
            "dns:\n"
            "  nameserver: [https://1.1.1.1/dns-query#RULES]\n"
            "  nameserver-policy: {\"geosite:cn\": [223.5.5.5, \"https://doh.pub/dns-query\"], "
            "\"+.google.com\": 8.8.8.8}\n"
        )
        client = proxydns.inspect_text(text, "x", system_dns=["8.8.8.8"])
        self.assertEqual(client["domesticPolicy"], [
            "223.5.5.5", "https://doh.pub/dns-query"])
        self.assertEqual(client["domesticDestination"], [])
        self.assertEqual(client["domesticProxied"], [])

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


class RelayTests(unittest.TestCase):
    """境外 DoH 有没有挂「查询走代理」的后缀。

    不挂后缀、内核的 respect-rules 又被客户端强制关掉（FlClash 生成配置时
    恒为 false），查询就从本机 IP 直接发出：解析器记下真实地址，而 DNS 泄漏
    探针只问解析器在哪，看不到这一层。
    """

    def test_plain_doh_is_missing_a_relay(self):
        self.assertTrue(proxydns.relay_missing("https://1.1.1.1/dns-query"))

    def test_relay_suffix_is_read_as_the_group_name(self):
        self.assertEqual(
            proxydns.relay_group("https://1.1.1.1/dns-query#PROXY"), "PROXY")
        self.assertFalse(proxydns.relay_missing("https://1.1.1.1/dns-query#PROXY"))

    def test_protocol_params_are_not_group_names(self):
        for value in ("https://dns.google/dns-query#h3",
                      "https://dns.google/dns-query#no-resolve"):
            self.assertEqual(proxydns.relay_group(value), "", value)
            self.assertTrue(proxydns.relay_missing(value), value)

    def test_mixed_suffix_keeps_the_group(self):
        self.assertEqual(
            proxydns.relay_group("https://dns.google/dns-query#PROXY#h3"), "PROXY")
        self.assertEqual(
            proxydns.relay_group("https://dns.google/dns-query#h3#PROXY"), "PROXY")

    def test_system_and_plain_ip_are_not_judged(self):
        for value in ("system", "dhcp://en0", "8.8.8.8", "tls://8.8.8.8"):
            self.assertFalse(proxydns.relay_missing(value), value)

    def test_inspect_reports_unrelayed_proxied_servers(self):
        text = FLCLASH.replace('"8.8.8.8"\n', '"https://1.1.1.1/dns-query"\n', 1)
        client = proxydns.inspect_text(text, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["unrelayed"], ["https://1.1.1.1/dns-query"])

    def test_domestic_doh_is_left_to_the_other_branch(self):
        # 国内解析器已经由 domesticProxied 报过，不在这里重复计一次。
        client = proxydns.inspect_text(FLCLASH, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["unrelayed"], [])

    def test_relayed_config_reports_nothing(self):
        text = FLCLASH.replace('"8.8.8.8"', '"https://1.1.1.1/dns-query#PROXY"')
        client = proxydns.inspect_text(text, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["unrelayed"], [])


class ProviderTests(unittest.TestCase):
    """nameserver 里挂了几家服务商。

    两家一起挂，内核会并行发查询、谁先回用谁，「DNS 出口」于是随查询在两家
    之间跳。不同厂商的递归出口策略不一样：Cloudflare 在入口 PoP 就地解析
    （地理跟着出口走），Google 常从自己的骨干网出去，出口在美东时可能报在
    蒙特利尔。这不是泄漏，但探针会把它画成两个国家。
    """

    MIXED = ('dns:\n'
             '  enable: true\n'
             '  nameserver:\n'
             '    - "https://1.1.1.1/dns-query#PROXY"\n'
             '    - "https://8.8.8.8/dns-query#PROXY"\n')

    def test_known_services_are_named(self):
        cases = {
            "https://1.1.1.1/dns-query": "cloudflare",
            "https://1.0.0.1/dns-query": "cloudflare",
            "https://dns.google/dns-query": "google",
            "tls://8.8.4.4": "google",
            "tls://9.9.9.9": "quad9",
            "https://dns.alidns.com/dns-query": "alidns",
            "https://doh.pub/dns-query": "dnspod",
            "system": "system",
        }
        for raw, want in cases.items():
            self.assertEqual(proxydns.provider(raw), want, raw)

    def test_relay_suffix_does_not_change_the_service(self):
        self.assertEqual(
            proxydns.provider("https://1.1.1.1/dns-query#PROXY"), "cloudflare")

    def test_unknown_service_is_not_silently_grouped(self):
        self.assertEqual(proxydns.provider("https://dns.example.org/q"), "other")
        self.assertEqual(proxydns.provider(""), "")

    def test_two_services_are_mixed(self):
        client = proxydns.inspect_text(self.MIXED, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["providers"], ["cloudflare", "google"])
        self.assertTrue(client["mixedProviders"])

    def test_one_service_with_two_addresses_is_not_mixed(self):
        text = self.MIXED.replace('"https://8.8.8.8/dns-query#PROXY"',
                                  '"https://1.0.0.1/dns-query#PROXY"')
        client = proxydns.inspect_text(text, "FlClash", system_dns=["8.8.8.8"])
        self.assertEqual(client["providers"], ["cloudflare"])
        self.assertFalse(client["mixedProviders"])

    def test_system_follows_the_host_and_is_not_a_service(self):
        text = ('dns:\n  nameserver:\n'
                '    - "system"\n'
                '    - "https://1.1.1.1/dns-query#PROXY"\n')
        client = proxydns.inspect_text(text, "FlClash", system_dns=["8.8.8.8"])
        self.assertFalse(client["mixedProviders"])

    def test_mixed_services_are_reported_as_low(self):
        client = proxydns.inspect_text(self.MIXED, "FlClash", system_dns=["8.8.8.8"])
        item = deep.check_proxy_dns(
            state={"tunneled": True},
            report={"system": ["8.8.8.8"], "systemDomestic": [], "clients": [client],
                    "domesticDestination": [], "domesticProxied": [],
                    "domesticDirect": [], "domesticBootstrap": [],
                    "domesticNode": [], "domesticPolicy": [],
                    "unrelayed": client["unrelayed"],
                    "providers": client["providers"],
                    "mixedProviders": client["mixedProviders"], "note": ""},
            resolver={"checked": True, "country": "CA", "isp": "Google"},
            egress={"country": "US"})
        self.assertEqual(item["severity"], "low")
        self.assertIn("多个服务商", item["title"])
        self.assertIn("Cloudflare", item["title"])
        self.assertIn("Google", item["title"])
        self.assertIn("1.0.0.1", item["advice"])
        self.assertEqual(item["dns"]["mixedProviders"], True)

    def test_single_service_stays_pass(self):
        text = self.MIXED.replace('"https://8.8.8.8/dns-query#PROXY"',
                                  '"https://1.0.0.1/dns-query#PROXY"')
        client = proxydns.inspect_text(text, "FlClash", system_dns=["8.8.8.8"])
        item = deep.check_proxy_dns(
            state={"tunneled": True},
            report={"system": ["8.8.8.8"], "systemDomestic": [], "clients": [client],
                    "domesticDestination": [], "domesticProxied": [],
                    "domesticDirect": [], "domesticBootstrap": [],
                    "domesticNode": [], "domesticPolicy": [],
                    "unrelayed": client["unrelayed"],
                    "providers": client["providers"],
                    "mixedProviders": client["mixedProviders"], "note": ""},
            resolver={"checked": True, "country": "US", "isp": "Cloudflare"},
            egress={"country": "US"})
        self.assertEqual(item["severity"], "pass")


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

    def test_running_client_policy_is_aggregated(self):
        text = FLCLASH.replace(
            "  nameserver-policy: null\n",
            "  nameserver-policy:\n"
            "    \"geosite:cn\":\n"
            "      - https://doh.pub/dns-query\n")
        (self.root / "config.yaml").write_text(text, encoding="utf-8")
        rep = self.collect(["/Applications/FlClash.app/Contents/MacOS/FlClash"])
        self.assertEqual(rep["domesticPolicy"], ["https://doh.pub/dns-query"])
        self.assertEqual(rep["clients"][0]["policy"], [
            {"selector": "geosite:cn", "server": "https://doh.pub/dns-query"}])

    def test_helper_and_service_processes_are_not_clients(self):
        for cmd in ("/Library/PrivilegedHelperTools/party.mihomo.helper",
                    "/Library/PrivilegedHelperTools/clash-verge-service",
                    "FlClashWidgetExtension"):
            self.assertEqual(self.collect([cmd])["clients"], [], cmd)


class DeepItemTests(unittest.TestCase):
    def test_tunneled_domestic_destination_is_medium(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"],
                     domesticNode=["223.5.5.5"])
        item = deep.check_proxy_dns(state={"tunneled": True}, report=rep, resolver={})
        self.assertEqual(item["id"], "net.proxy_dns")
        self.assertEqual(item["severity"], "medium")
        self.assertIn("doh.pub", item["title"])
        self.assertIn("节点域名", item["detail"])
        self.assertIn("dns", item)

    def test_configured_but_not_tunneled_is_info(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"])
        item = deep.check_proxy_dns(state={"tunneled": False}, report=rep, resolver={})
        self.assertEqual(item["severity"], "info")
        self.assertIn("没有接管", item["detail"])

    def test_clean_proxy_is_pass(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report(), resolver={})
        self.assertEqual(item["severity"], "pass")

    def test_unreadable_proxy_is_info_not_pass(self):
        item = deep.check_proxy_dns(
            state={"tunneled": True}, resolver={},
            report=report(clients=[], note="没找到运行中的客户端配置，读不到它的 DNS 名单"))
        self.assertEqual(item["severity"], "info")
        self.assertIn("不代表没有国内解析器", item["detail"])

    def test_no_config_mentions_system_dns(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report(), resolver={})
        labels = [e["label"] for e in item["evidence"]]
        self.assertIn("系统 DNS", labels)


def measured(country="CN", org="CHINANET", masked="219.128.*.150") -> dict:
    return {"checked": True, "ip": "219.128.79.150", "masked": masked,
            "country": country, "org": org, "domestic": country == "CN", "at": 0}


class ResolverEgressTests(unittest.TestCase):
    """fake-ip 只证明查询被接管，证明不了后面由谁解析。名单干净时，
    实测出口是唯一能看见泄漏的地方。"""

    def test_parse_skips_labels_and_quotes(self):
        self.assertEqual(resolveregress.parse('"219.128.79.150"'), "219.128.79.150")
        self.assertEqual(resolveregress.parse('"ns1.google.com" "2001:db8::1"'),
                         "2001:db8::1")
        self.assertEqual(resolveregress.parse(""), "")

    def test_clean_config_but_domestic_resolver_is_medium(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report(),
                                    resolver=measured())
        self.assertEqual(item["severity"], "medium")
        self.assertIn("解析器出口在国内", item["title"])
        self.assertIn("CHINANET", item["detail"])
        self.assertEqual(item["dns"]["resolver"]["country"], "CN")

    def test_clean_config_and_foreign_resolver_is_pass(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report(),
                                    resolver=measured(country="US", org="GOOGLE"))
        self.assertEqual(item["severity"], "pass")
        self.assertIn("GOOGLE", item["detail"])

    def test_direct_only_domestic_with_foreign_egress_is_info(self):
        """直连域名用国内解析器是常态：代理域名走境外 DoH、实测出口也在境外，
        不能因为 direct-nameserver 里写着 doh.pub 就报中危。"""
        domestic = ["https://doh.pub/dns-query", "223.5.5.5"]
        rep = report(domesticDestination=domestic, domesticProxied=[],
                     domesticDirect=domestic)
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=rep,
            resolver=measured(country="US", org="Cloudflare, Inc."))
        self.assertEqual(item["severity"], "info")
        self.assertIn("直连域名用国内解析器", item["title"])
        self.assertIn("Cloudflare", item["detail"])

    def test_direct_only_domestic_with_domestic_egress_is_medium(self):
        domestic = ["https://doh.pub/dns-query"]
        rep = report(domesticDestination=domestic, domesticProxied=[],
                     domesticDirect=domestic)
        item = deep.check_proxy_dns(state={"tunneled": True}, report=rep,
                                    resolver=measured())
        self.assertEqual(item["severity"], "medium")
        self.assertIn("解析器出口在国内", item["title"])
        self.assertIn("直连域名", item["detail"])

    def test_policy_only_domestic_is_info_with_foreign_egress(self):
        """nameserver-policy 只服务国内域名：代理域名仍走境外 DoH，不能当泄漏报。"""
        server = "https://doh.pub/dns-query"
        rep = report(domesticDestination=[server], domesticProxied=[],
                     domesticPolicy=[server],
                     policy=[{"selector": "geosite:cn", "server": server}])
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=rep,
            resolver=measured(country="US", org="Cloudflare, Inc."))
        self.assertEqual(item["severity"], "info")
        self.assertIn("国内域名用国内解析器", item["title"])
        self.assertIn("GEOIP,CN", item["detail"])
        self.assertEqual(item["dns"]["domesticPolicy"], [server])
        self.assertIn("国内域名解析用", [e["label"] for e in item["evidence"]])

    def test_unreadable_config_with_domestic_resolver_is_medium(self):
        item = deep.check_proxy_dns(
            state={"tunneled": True}, resolver=measured(),
            report=report(clients=[], note="没找到运行中的客户端配置"))
        self.assertEqual(item["severity"], "medium")
        self.assertIn("解析器出口在国内", item["title"])

    def test_full_ip_never_reaches_the_report(self):
        item = deep.check_proxy_dns(state={"tunneled": True}, report=report(),
                                    resolver=measured())
        blob = repr(item)
        self.assertNotIn("219.128.79.150", blob)
        self.assertIn("219.128.*.150", blob)

    def test_no_egress_means_no_probe(self):
        """没有出口时查一次，等于自己制造一次泄漏。"""
        with mock.patch.object(resolveregress, "probe") as probe:
            deep.check_proxy_dns(state={"tunneled": False}, report=report())
        probe.assert_not_called()

    def test_probe_runs_when_tunnel_is_up(self):
        with mock.patch.object(resolveregress, "probe", return_value=measured()) as probe:
            item = deep.check_proxy_dns(state={"tunneled": True}, report=report())
        probe.assert_called_once()
        self.assertEqual(item["severity"], "medium")


class CountryMismatchTests(unittest.TestCase):
    """解析器国家与此次 HTTP 出口国家。两者不同不是国内解析，但外部探针
    会把「DNS 国家」标红，所以记低风险，而不是替用户判成一致。"""

    def run_check(self, resolver_country="US", egress_country="US", **rep):
        return deep.check_proxy_dns(
            state={"tunneled": True}, report=report(**rep),
            resolver=measured(country=resolver_country, org="Cloudflare, Inc."),
            egress={"available": True, "ip": "203.0.113.9",
                    "ip_masked": "203.0.*.9", "country": egress_country})

    def test_same_country_is_pass_and_records_both(self):
        item = self.run_check("US", "US")
        self.assertEqual(item["severity"], "pass")
        self.assertEqual(item["dns"]["resolverCountry"], "US")
        self.assertEqual(item["dns"]["egressCountry"], "US")
        self.assertFalse(item["dns"]["countryMismatch"])

    def test_different_country_is_low(self):
        item = self.run_check("US", "JP")
        self.assertEqual(item["severity"], "low")
        self.assertIn("解析器国家与出口不一致（US / JP）", item["title"])
        self.assertIn("HTTP 出口在 JP", item["detail"])
        self.assertIn("同区", item["advice"])
        self.assertIn("出口国家", [e["label"] for e in item["evidence"]])
        self.assertTrue(item["dns"]["countryMismatch"])

    def test_no_egress_country_does_not_invent_a_mismatch(self):
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=report(),
            resolver=measured(country="US", org="Cloudflare, Inc."), egress={})
        self.assertEqual(item["severity"], "pass")
        self.assertFalse(item["dns"]["countryMismatch"])
        self.assertNotIn("出口国家", [e["label"] for e in item["evidence"]])

    def test_domestic_resolver_still_wins_over_mismatch(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"])
        item = self.run_check("CN", "JP", **rep)
        self.assertEqual(item["severity"], "medium")
        self.assertIn("本次 HTTP 出口在 JP，解析器在 CN", item["detail"])

    def test_policy_branch_mentions_the_mismatch(self):
        server = "https://doh.pub/dns-query"
        rep = dict(domesticDestination=[server], domesticProxied=[],
                   domesticPolicy=[server],
                   policy=[{"selector": "geosite:cn", "server": server}])
        item = self.run_check("US", "JP", **rep)
        self.assertEqual(item["severity"], "info")
        self.assertIn("它的归属是 US，本次出口在 JP", item["detail"])

    def test_unreadable_config_mentions_mismatch_without_changing_severity(self):
        item = self.run_check("US", "JP", clients=[],
                              note="没找到运行中的客户端配置")
        self.assertEqual(item["severity"], "info")
        self.assertIn("实测递归出口在 US，本次出口在 JP", item["detail"])

    def test_quiet_card_surfaces_the_mismatch(self):
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=report(),
            resolver=measured(country="US", org="Cloudflare, Inc."),
            egress={"available": True, "country": "JP"})
        route = {"id": "net.dns_route", "title": "DNS 已被代理接管"}
        out = tower._probe_proxy(scan(*BASE_ITEMS, item, route), {})
        self.assertEqual(out["sev"], "low")
        self.assertIn("解析器出口在 US，出口在 JP", out["value"])
        self.assertIn("出口国家", [e["label"] for e in out["evidence"]])
        self.assertNotIn("act", out)

    def test_leak_card_names_both_countries(self):
        rep = report(domesticDestination=["https://doh.pub/dns-query"])
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=rep, resolver=measured(),
            egress={"available": True, "country": "JP"})
        route = {"id": "net.dns_route", "title": "DNS 已被代理接管"}
        out = tower._probe_proxy(scan(*BASE_ITEMS, item, route), {})
        self.assertEqual(out["sev"], "medium")
        self.assertIn("出口在 JP，解析器在 CN", out["detail"])
        self.assertIn("出口国家", [e["label"] for e in out["evidence"]])


class TowerProbeTests(unittest.TestCase):
    def probe(self, rep, route, pitem=None):
        item = pitem or deep.check_proxy_dns(
            state={"tunneled": True}, report=rep, resolver={})
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
        item = deep.check_proxy_dns(state={"tunneled": False}, report=rep, resolver={})
        out = self.probe(rep, {"id": "net.dns_route", "title": "DNS 已被代理接管"},
                         pitem=item)
        self.assertNotEqual(out["sev"], "medium")
        self.assertIn("没接管流量", out["value"])

    def test_measured_resolver_leak_reaches_the_card(self):
        rep = report()
        item = deep.check_proxy_dns(state={"tunneled": True}, report=rep,
                                    resolver=measured())
        out = self.probe(rep, {"id": "net.dns_route", "title": "DNS 已被代理接管"},
                         pitem=item)
        self.assertEqual(out["sev"], "medium")
        self.assertIn("实测解析出口", out["value"])
        self.assertIn("219.128.*.150", out["value"])
        self.assertIn("解析出口", out["advice"])

    def test_policy_only_card_names_the_domestic_domain_role(self):
        server = "https://doh.pub/dns-query"
        rep = report(domesticDestination=[server], domesticProxied=[],
                     domesticPolicy=[server],
                     policy=[{"selector": "geosite:cn", "server": server}])
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=rep,
            resolver=measured(country="US", org="Cloudflare, Inc."))
        out = self.probe(rep, {"id": "net.dns_route", "title": "DNS 已被代理接管"},
                         pitem=item)
        self.assertEqual(out["sev"], "info")
        self.assertIn("国内域名", out["value"])
        labels = [e["label"] for e in out["evidence"]]
        self.assertIn("国内域名解析用", labels)
        self.assertIn("实测解析出口", labels)
        self.assertIn("系统 DNS", labels)
        self.assertNotIn("act", out)

    def test_direct_only_card_does_not_claim_a_proxy_leak(self):
        server = "https://doh.pub/dns-query"
        rep = report(domesticDestination=[server], domesticProxied=[],
                     domesticDirect=[server])
        item = deep.check_proxy_dns(
            state={"tunneled": True}, report=rep,
            resolver=measured(country="US", org="Cloudflare, Inc."))
        out = self.probe(rep, {"id": "net.dns_route", "title": "DNS 已被代理接管"},
                         pitem=item)
        self.assertEqual(out["sev"], "info")
        self.assertIn("直连域名", out["value"])
        self.assertIn("直连域名解析用", [e["label"] for e in out["evidence"]])
        self.assertNotIn("act", out)

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
        self.assertIn('pd.get("resolver")', tw)

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
