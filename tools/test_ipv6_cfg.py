#!/usr/bin/env python3
"""IPv6 关闭 / 恢复状态机回归：全部在内存里跑，绝不提权或改真实网络。

    python3 tools/test_ipv6_cfg.py
"""

from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import ipv6cfg


class IPv6Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / ".ccclean/ipv6-state.json"
        self.modes = {"Wi-Fi": "Automatic", "USB LAN": "Automatic", "Old VPN": "Off"}
        self.enabled = ["Wi-Fi", "USB LAN"]
        self.fail = None
        self.set_calls = []

        for target, val in [("STATE", self.state),
                            ("NETWORKSETUP", "/usr/sbin/networksetup")]:
            p = patch.object(ipv6cfg, target, val)
            p.start()
            self.addCleanup(p.stop)
        for target, val in [("IS_MAC", True),
                            ("ipv6_exposure", lambda: {"has_global_v6": True,
                                                       "has_default_v6_route": True})]:
            p = patch.object(ipv6cfg.compat, target, val)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(ipv6cfg, "_run", side_effect=self.fake_run)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(ipv6cfg, "_set_modes", side_effect=self.set_modes)
        p.start()
        self.addCleanup(p.stop)

    def fake_run(self, args, timeout=8):
        if args[1] == "-listallnetworkservices":
            return ("An asterisk (*) denotes that a network service is disabled.\n"
                    + "\n".join(self.enabled + ["*Old VPN"]) + "\n")
        if args[1] == "-getinfo":
            return f"DHCP Configuration\nIPv6: {self.modes.get(args[2], '')}\n"
        return ""

    def set_modes(self, jobs):
        self.set_calls.append(list(jobs))
        for name, flag in jobs:
            if name == self.fail:
                raise RuntimeError("cancelled")
            self.modes[name] = "Off" if flag == "-setv6off" else "Automatic"

    def test_status_lists_enabled_services_and_marks_wifi(self):
        s = ipv6cfg.status()
        self.assertEqual([r["name"] for r in s["services"]], self.enabled)
        self.assertEqual(s["wifi"], "Wi-Fi")
        self.assertEqual(s["wifiMode"], "Automatic")
        self.assertEqual(s["automatic"], ["Wi-Fi"])
        self.assertEqual(s["disabled"], [])
        self.assertFalse(s["applied"])
        self.assertFalse(s["restoreAvailable"])

    def test_off_only_touches_wifi(self):
        s = ipv6cfg.apply("off")
        self.assertTrue(s["applied"])
        self.assertEqual(s["changed"], ["Wi-Fi"])
        self.assertEqual(self.modes["Wi-Fi"], "Off")
        self.assertEqual(self.modes["USB LAN"], "Automatic")
        self.assertTrue(self.state.exists())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 1)
        self.assertEqual(list(saved["services"]), ["Wi-Fi"])

        with self.assertRaises(ValueError):
            ipv6cfg.apply("off")  # 未恢复前不叠加第二次改动

        s = ipv6cfg.apply("restore")
        self.assertFalse(s["restoreAvailable"])
        self.assertFalse(s["applied"])
        self.assertFalse(self.state.exists())
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")
        self.assertEqual(self.modes["USB LAN"], "Automatic")

    def test_cancel_leaves_no_state(self):
        self.fail = "Wi-Fi"
        with self.assertRaises(RuntimeError):
            ipv6cfg.apply("off")
        self.assertFalse(self.state.exists())
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")
        self.assertEqual(self.modes["USB LAN"], "Automatic")

    def test_legacy_record_restores_every_service_it_names(self):
        """2.12.0 的记录可能含多个服务；升级后仍要能完整撤销。"""
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text(json.dumps({
            "version": 1, "createdAt": 1, "services": {
                "Wi-Fi": "Automatic", "USB LAN": "Automatic"}}), encoding="utf-8")
        self.modes["Wi-Fi"] = "Off"
        self.modes["USB LAN"] = "Off"
        s = ipv6cfg.apply("restore")
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")
        self.assertEqual(self.modes["USB LAN"], "Automatic")
        self.assertIn("已恢复 2 个", s["message"])
        self.assertFalse(self.state.exists())

    def test_legacy_partial_failure_keeps_state(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text(json.dumps({
            "version": 1, "createdAt": 1, "services": {
                "Wi-Fi": "Automatic", "USB LAN": "Automatic"}}), encoding="utf-8")
        self.modes["Wi-Fi"] = "Off"
        self.modes["USB LAN"] = "Off"
        self.fail = "USB LAN"
        with self.assertRaises(RuntimeError):
            ipv6cfg.apply("restore")
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")
        self.assertEqual(self.modes["USB LAN"], "Off")
        self.assertTrue(self.state.exists())

    def test_manual_change_is_not_overwritten(self):
        ipv6cfg.apply("off")
        self.modes["Wi-Fi"] = "Link-local only"
        s = ipv6cfg.apply("restore")
        self.assertEqual(self.modes["Wi-Fi"], "Link-local only")
        self.assertIn("未覆盖", s["message"])

    def test_no_wifi_service_is_refused(self):
        self.enabled = ["USB LAN"]
        with self.assertRaises(ValueError):
            ipv6cfg.apply("off")
        self.assertFalse(self.state.exists())
        self.assertEqual(self.modes["USB LAN"], "Automatic")
        self.assertTrue(ipv6cfg.status()["wifiError"])

    def test_wifi_not_automatic_is_refused(self):
        self.modes["Wi-Fi"] = "Off"
        with self.assertRaises(ValueError):
            ipv6cfg.apply("off")
        self.assertFalse(self.state.exists())

    def test_restore_without_record(self):
        with self.assertRaises(ValueError):
            ipv6cfg.apply("restore")

    def test_corrupt_state_blocks_restore_but_status_reports(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("{not json", encoding="utf-8")
        s = ipv6cfg.status()
        self.assertTrue(s["stateError"])
        self.assertFalse(s["restoreAvailable"])
        with self.assertRaises(ValueError):
            ipv6cfg.apply("restore")
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")

    def test_symlink_state_refused(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        target = self.root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.state.symlink_to(target)
        with self.assertRaises(ValueError):
            ipv6cfg.apply("off")
        self.assertEqual(self.modes["Wi-Fi"], "Automatic")

    def test_stale_record_is_cleared_without_admin(self):
        ipv6cfg.apply("off")
        self.modes["Wi-Fi"] = "Automatic"
        before = len(self.set_calls)
        s = ipv6cfg.apply("restore")
        self.assertEqual(len(self.set_calls), before)  # 没有需要改的服务，不该提权
        self.assertFalse(self.state.exists())
        self.assertIn("已恢复 0 个", s["message"])

    def test_read_failure_keeps_record(self):
        ipv6cfg.apply("off")
        with patch.object(ipv6cfg, "_run", return_value=""):
            with self.assertRaises(RuntimeError):
                ipv6cfg.apply("restore")
        self.assertTrue(self.state.exists())

    def test_unknown_mode_keeps_record(self):
        ipv6cfg.apply("off")
        del self.modes["Wi-Fi"]  # 读不到这个服务的状态
        with self.assertRaises(RuntimeError):
            ipv6cfg.apply("restore")
        self.assertTrue(self.state.exists())

    def test_script_quotes_service_names(self):
        script = ipv6cfg._script([("Wi-Fi", "-setv6off"),
                                  ("Bob's LAN", "-setv6off")])
        self.assertTrue(script.startswith("set -eu\n"))
        self.assertIn("/usr/sbin/networksetup -setv6off Wi-Fi", script)
        self.assertIn("'Bob'\"'\"'s LAN'", script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
