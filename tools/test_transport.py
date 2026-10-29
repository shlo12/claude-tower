#!/usr/bin/env python3
"""P0/P1 网络判据：代理链路、TUN、DNS、IPv6 范围、国家预期、多客户端判活。

全部打桩，不读真实网络、不改系统设置。重点是防误报：
系统代理不需要 TUN、真实 DNS 在链路已接管时不判高危、非 Wi-Fi v6 不冒充可修复项。
"""
from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import compat, deep, netcfg, scanner


def state(**kw) -> dict:
    base = {
        "system_proxy_on": False,
        "system_proxy": {},
        "default_iface": "en0",
        "tun_on": False,
        "fake_route": "",
        "fake_route_on": False,
        "tunneled": False,
        "processes": [],
        "vpns": [],
        "tun_configured": False,
    }
    base.update(kw)
    base["tunneled"] = bool(base["tun_on"] or base["fake_route_on"]
                            or base["system_proxy_on"])
    return base


class ProxyPathTests(unittest.TestCase):
    def test_no_path_is_high(self):
        out = deep.check_proxy_path(state())
        self.assertEqual(out["id"], "net.proxy_path")
        self.assertEqual(out["severity"], "high")

    def test_system_proxy_alone_is_a_path(self):
        out = deep.check_proxy_path(state(
            system_proxy_on=True,
            system_proxy={"server": "127.0.0.1:7890"},
        ))
        self.assertEqual(out["severity"], "pass")
        self.assertIn("系统代理", out["title"])

    def test_shadowrocket_vpn_is_a_path(self):
        out = deep.check_proxy_path(state(vpns=["Shadowrocket"]))
        self.assertEqual(out["severity"], "pass")
        self.assertTrue(any("Shadowrocket" in e["value"] for e in out["evidence"]))

    def test_tun_alone_is_a_path(self):
        out = deep.check_proxy_path(state(tun_on=True))
        self.assertEqual(out["severity"], "pass")
        self.assertIn("TUN", out["title"])

    def test_local_listener_is_a_path(self):
        out = deep.check_proxy_path(state(processes=["mihomo"]))
        self.assertEqual(out["severity"], "pass")


class TunTests(unittest.TestCase):
    def test_no_tun_and_not_configured_is_info(self):
        # 系统代理用户不该被 TUN 扣分
        out = deep.check_tun(state(system_proxy_on=True,
                                   system_proxy={"server": "127.0.0.1:7890"}))
        self.assertEqual(out["severity"], "info")
        self.assertNotEqual(out["severity"], "high")

    def test_configured_but_missing_is_high(self):
        out = deep.check_tun(state(tun_configured=True))
        self.assertEqual(out["severity"], "high")
        self.assertIn("默认路由", out["title"])

    def test_configured_but_system_proxy_active_is_info(self):
        # 配置里写了 TUN，但系统代理已经承载流量：不判泄漏
        out = deep.check_tun(state(tun_configured=True, system_proxy_on=True,
                                   system_proxy={"server": "127.0.0.1:7890"}))
        self.assertEqual(out["severity"], "info")

    def test_tun_on_is_pass(self):
        out = deep.check_tun(state(tun_on=True))
        self.assertEqual(out["severity"], "pass")


class DnsRouteTests(unittest.TestCase):
    REAL = {"claude.ai": "real", "api.anthropic.com": "real",
            "claudeusercontent.com": "real"}
    FAKE = {"claude.ai": "fake", "api.anthropic.com": "fake",
            "claudeusercontent.com": "fake"}

    def test_real_dns_without_path_is_high(self):
        out = deep.check_dns_route(self.REAL, state())
        self.assertEqual(out["severity"], "high")
        self.assertEqual(out["id"], "net.dns_route")

    def test_real_dns_with_system_proxy_is_info(self):
        out = deep.check_dns_route(self.REAL, state(system_proxy_on=True))
        self.assertEqual(out["severity"], "info")

    def test_real_dns_with_tun_is_info(self):
        out = deep.check_dns_route(self.REAL, state(tun_on=True))
        self.assertEqual(out["severity"], "info")

    def test_fake_dns_is_pass(self):
        out = deep.check_dns_route(self.FAKE, state())
        self.assertEqual(out["severity"], "pass")

    def test_mixed_dns_is_info(self):
        mixed = dict(self.REAL, **{"claude.ai": "fake"})
        self.assertEqual(deep.check_dns_route(mixed, state())["severity"], "info")

    def test_offline_is_info(self):
        out = deep.check_dns_route(
            {"claude.ai": "unchecked", "api.anthropic.com": "unchecked",
             "claudeusercontent.com": "unchecked"}, state())
        self.assertEqual(out["severity"], "info")


class Ipv6ScopeTests(unittest.TestCase):
    def run_with(self, exposure, wifi="en0", mac=True):
        with mock.patch.object(deep.compat, "ipv6_exposure", return_value=exposure), \
             mock.patch.object(deep.compat, "wifi_device", return_value=wifi), \
             mock.patch.object(deep.compat, "IS_MAC", mac):
            return deep.check_ipv6()

    def test_no_global_is_pass(self):
        out = self.run_with({"sample": [], "has_default_v6_route": False})
        self.assertEqual(out["severity"], "pass")

    def test_wifi_default_route_is_actionable(self):
        out = self.run_with({
            "sample": ["2408:1::1"],
            "has_default_v6_route": True,
            "default_v6_iface": "en0",
            "interfaces": {"en0": ["2408:1::1"]},
        })
        self.assertEqual(out["severity"], "medium")
        self.assertIn("Wi-Fi", out["title"])
        self.assertIn("IPv6 出口（Wi-Fi）", out["advice"])

    def test_non_wifi_route_is_info_and_manual(self):
        # 以太网上的 v6 不是本工具能修的，不能报成可一键关闭的中风险
        out = self.run_with({
            "sample": ["2408:1::1"],
            "has_default_v6_route": True,
            "default_v6_iface": "en5",
            "interfaces": {"en0": [], "en5": ["2408:1::1"]},
        })
        self.assertEqual(out["severity"], "info")
        self.assertIn("手动处理", out["advice"])
        self.assertNotIn("IPv6 出口（Wi-Fi）", out["advice"])


class CountryExpectationTests(unittest.TestCase):
    def test_unset_makes_no_judgment(self):
        self.assertIsNone(scanner._country_expectation("US", ""))

    def test_match_is_pass(self):
        out = scanner._country_expectation("us", "US", "5.34.*.136")
        self.assertEqual(out["severity"], "pass")
        self.assertEqual(out["id"], "net.country")

    def test_mismatch_is_high_without_auto_region_change(self):
        out = scanner._country_expectation("JP", "US", "5.34.*.136")
        self.assertEqual(out["severity"], "high")
        self.assertIn("不会自动改地区", out["advice"])

    def test_unknown_country_is_info(self):
        out = scanner._country_expectation("", "US")
        self.assertEqual(out["severity"], "info")


class NetcfgStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ccclean-netcfg-")
        self.old = netcfg.CONFIG
        netcfg.CONFIG = Path(self.tmp.name) / ".ccclean" / "netcfg.json"

    def tearDown(self):
        netcfg.CONFIG = self.old
        self.tmp.cleanup()

    def test_saves_uppercase_and_0600(self):
        out = netcfg.set_country("us")
        self.assertEqual(out["country"], "US")
        self.assertEqual(stat.S_IMODE(netcfg.CONFIG.stat().st_mode), 0o600)
        self.assertEqual(json.loads(netcfg.CONFIG.read_text())["expectedCountry"], "US")

    def test_invalid_value_does_not_overwrite(self):
        netcfg.set_country("US")
        with self.assertRaises(ValueError):
            netcfg.set_country("USA")
        self.assertEqual(netcfg.expected_country(), "US")

    def test_empty_clears(self):
        netcfg.set_country("JP")
        self.assertEqual(netcfg.set_country("")["country"], "")
        self.assertEqual(netcfg.expected_country(), "")

    def test_corrupt_file_is_not_a_judgment(self):
        netcfg.CONFIG.parent.mkdir(parents=True)
        netcfg.CONFIG.write_text("{not json", encoding="utf-8")
        self.assertEqual(netcfg.expected_country(), "")
        self.assertTrue(netcfg.status()["error"])


class ClientDetectionTests(unittest.TestCase):
    def test_socks_only_system_proxy(self):
        sample = ("<dictionary> {\n"
                  "  HTTPEnable : 0\n  HTTPSEnable : 0\n"
                  "  SOCKSEnable : 1\n  SOCKSProxy : 127.0.0.1\n  SOCKSPort : 1080\n}")
        with mock.patch.object(compat, "IS_MAC", True), \
             mock.patch.object(compat, "run", return_value=sample):
            out = compat.system_proxy()
        self.assertTrue(out["enabled"])
        self.assertEqual(out["server"], "127.0.0.1:1080")
        self.assertEqual(out["schemes"], ["SOCKS"])

    def test_shadowrocket_connected(self):
        sample = ('Available network connection services in the current set:\n'
                  '* (Connected)      UUID com.liguangming.Shadowrocket "Shadowrocket" [VPN:TUN]\n'
                  '  (Disconnected)   UUID com.apple.vpn "Office" [VPN]')
        with mock.patch.object(compat, "IS_MAC", True), \
             mock.patch.object(compat, "run", return_value=sample):
            self.assertEqual(compat.proxy_vpn_connections(), ["Shadowrocket"])

    def test_corporate_vpn_is_not_a_proxy(self):
        sample = ('* (Connected)      UUID com.corp.vpn "Office VPN" [VPN]')
        with mock.patch.object(compat, "IS_MAC", True), \
             mock.patch.object(compat, "run", return_value=sample):
            self.assertEqual(compat.proxy_vpn_connections(), [])

    def test_tun_config_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="ccclean-tun-cfg-") as tmp:
            root = Path(tmp)
            (root / "config.yaml").write_text("tun:\n  enable: true\n", encoding="utf-8")
            with mock.patch.object(deep, "_CLASH_ROOTS", [root]):
                self.assertTrue(deep._tun_enabled_in_configs())


if __name__ == "__main__":
    unittest.main(verbosity=2)
