#!/usr/bin/env python3
"""五个新检查项的判定逻辑测试。

这三项的共同点是「结果取决于跑测试那台机器当天装了什么」：客户端语言在
用户自己的 defaults 域里，哨兵状态在 ~/.claude-shield.json 里，代理规则在
用户随便哪个 yaml 里。所以全部走打桩——真正要固定下来的是**判据**，
不是某个人的机器。

    python3 tools/test_findings.py
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import deep, scanner


class ClientLangTests(unittest.TestCase):
    """客户端自己的界面语言。系统中文 + 客户端中文不算新增线索。"""

    def run_with(self, client: list[str], system: list[str], present: bool = True) -> dict:
        orig = scanner._client_language_state
        scanner._client_language_state = lambda: (client, present)
        try:
            return scanner._check_client_lang(system)
        finally:
            scanner._client_language_state = orig

    def test_missing_domain_is_info_not_pass(self):
        # 客户端没装/没启动过，读不到 ≠ 跟随系统。不能当成通过。
        out = self.run_with([], ["zh-Hans-CN"], present=False)
        self.assertEqual(out["severity"], "info")
        self.assertEqual(out["id"], "locale.client_lang")
        self.assertIn("读不到", out["title"])

    def test_no_override_is_pass(self):
        # 域在、键不在：客户端跟随系统，无从下手也没什么可挑
        out = self.run_with([], ["zh-Hans-CN"])
        self.assertEqual(out["severity"], "pass")
        self.assertEqual(out["id"], "locale.client_lang")

    def test_english_client_is_pass(self):
        out = self.run_with(["en-US"], ["en-US"])
        self.assertEqual(out["severity"], "pass")

    def test_both_chinese_is_only_low(self):
        # 系统本来就是中文，客户端也是中文：同一件事说两遍，不该重复扣分
        out = self.run_with(["zh-Hans-CN"], ["zh-Hans-CN"])
        self.assertEqual(out["severity"], "low")

    def test_english_system_chinese_client_is_medium(self):
        # 只改了系统设置的人最常漏掉的一层，也是唯一有画像价值的一档
        out = self.run_with(["zh-Hant-TW"], ["en-US"])
        self.assertEqual(out["severity"], "medium")
        self.assertIn("hard-signal", out["tags"])
        self.assertTrue(out["advice"], "medium 必须给出改法")

    def test_zh_prefix_matching_is_case_insensitive(self):
        out = self.run_with(["ZH-hans"], ["en-US"])
        self.assertEqual(out["severity"], "medium")

    def test_evidence_always_has_both_sides(self):
        out = self.run_with(["zh-Hans-CN"], ["en-US"])
        labels = [e["label"] for e in out["evidence"]]
        self.assertIn("客户端语言", labels)
        self.assertIn("系统语言", labels)


class ShieldPresenceTests(unittest.TestCase):
    """哨兵在不在。四档对应四种「没人看着」的程度。"""

    def run_with(self, status: dict) -> dict:
        orig = scanner.shield.status
        scanner.shield.status = lambda: status
        try:
            items = scanner.check_shield()
        finally:
            scanner.shield.status = orig
        self.assertEqual(len(items), 1, "这一项只产出一条")
        return items[0]

    def test_not_installed_is_medium(self):
        out = self.run_with({"app": {"installed": False}, "baseline": {}})
        self.assertEqual(out["severity"], "medium")
        self.assertIn("未安装", out["title"])
        self.assertTrue(out["advice"])

    def test_installed_not_running_is_medium(self):
        out = self.run_with({"app": {"installed": True, "running": False}, "baseline": {}})
        self.assertEqual(out["severity"], "medium")
        self.assertIn("没在运行", out["title"])

    def test_running_but_disabled_is_low(self):
        # 进程在、开关关着：比完全没装轻，但仍然是「没人看着」
        out = self.run_with(
            {"app": {"installed": True, "running": True, "enabled": False, "level": 2},
             "baseline": {}})
        self.assertEqual(out["severity"], "low")

    def test_running_and_enabled_is_pass(self):
        out = self.run_with(
            {"app": {"installed": True, "running": True, "enabled": True, "level": 2},
             "baseline": {"tz": "Asia/Singapore", "ip": "5.34.*.136"}})
        self.assertEqual(out["severity"], "pass")
        self.assertIn("断了就停", out["title"])

    def test_running_from_repo_is_online_even_if_not_installed(self):
        # 开发时从仓库直接跑 .app：在线是在线，不能因为不在 /Applications 就报未安装
        out = self.run_with(
            {"app": {"installed": False, "running": True, "enabled": True},
             "baseline": {}})
        self.assertEqual(out["severity"], "pass")
        vals = {e["label"]: e["value"] for e in out["evidence"]}
        self.assertIn("仓库内运行", vals["安装"])

    def test_launch_agent_state_is_reported(self):
        out = self.run_with(
            {"app": {"installed": True, "running": True, "enabled": True,
                     "launchAgent": "installed"}, "baseline": {}})
        vals = {e["label"]: e["value"] for e in out["evidence"]}
        self.assertEqual(vals["开机自启"], "已安装但未加载")

    def test_enabled_defaults_to_true(self):
        # 老版本状态文件里没有 enabled 这个键，不能因此判成「已停用」
        out = self.run_with(
            {"app": {"installed": True, "running": True}, "baseline": {}})
        self.assertEqual(out["severity"], "pass")

    def test_baseline_age_shown_in_hours(self):
        out = self.run_with(
            {"app": {"installed": True, "running": True, "enabled": True},
             "baseline": {"tz": "Asia/Tokyo", "ip": "1.2.*.4", "ipAge": 7200}})
        vals = {e["label"]: e["value"] for e in out["evidence"]}
        self.assertEqual(vals["出口记录于"], "2 小时前")

    def test_missing_baseline_does_not_crash(self):
        out = self.run_with({})
        self.assertEqual(out["severity"], "medium")


class PinnedRuleTests(unittest.TestCase):
    """生态域名被分到哪去了。这里只看规则解析，不看本机配置。"""

    def test_direct_is_blocked(self):
        pinned, blocked = deep.classify_rules("- DOMAIN-SUFFIX,anthropic.com,DIRECT")
        self.assertEqual(pinned, [])
        self.assertEqual(len(blocked), 1)

    def test_reject_is_blocked(self):
        _, blocked = deep.classify_rules("- DOMAIN-SUFFIX,claude.ai,REJECT")
        self.assertEqual(len(blocked), 1)

    def test_proxy_group_is_pinned(self):
        pinned, blocked = deep.classify_rules("- DOMAIN-SUFFIX,anthropic.com,🚀 节点选择")
        self.assertEqual(blocked, [])
        self.assertEqual(pinned, ["anthropic.com → 🚀 节点选择"])

    def test_domain_keyword_form_is_recognised(self):
        # 规则集里常见 `DOMAIN-KEYWORD,anthropic`，没有 .com，按完整域名匹配会漏
        _, blocked = deep.classify_rules("- DOMAIN-KEYWORD,anthropic,REJECT")
        self.assertEqual(len(blocked), 1)

    def test_geosite_form_is_recognised(self):
        pinned, _ = deep.classify_rules("- GEOSITE,anthropic,PROXY")
        self.assertEqual(len(pinned), 1)

    def test_quoted_policy_and_trailing_comment(self):
        pinned, _ = deep.classify_rules('- "DOMAIN-SUFFIX,api.anthropic.com,PROXY"  # 注释')
        self.assertEqual(len(pinned), 1)
        self.assertIn("PROXY", pinned[0])

    def test_chinese_policy_names(self):
        _, blocked = deep.classify_rules("- DOMAIN-SUFFIX,claude.com,直连")
        self.assertEqual(len(blocked), 1)

    def test_unrelated_rules_ignored(self):
        pinned, blocked = deep.classify_rules(
            "- DOMAIN-SUFFIX,google.com,PROXY\n- IP-CIDR,1.2.3.0/24,DIRECT")
        self.assertEqual((pinned, blocked), ([], []))

    def test_proxy_definition_is_not_a_rule(self):
        # 节点定义里也有 claude 和逗号，但它不是规则；更不能把密码当策略
        text = ("- {name: Claude, type: ss, server: 1.2.3.4, port: 443, "
                "cipher: aes-128-gcm, password: supersecret}")
        self.assertEqual(deep.classify_rules(text), ([], []))

    def test_comment_is_not_a_rule(self):
        self.assertEqual(deep.classify_rules("# 给 Claude 加规则, 顺便记一下, 这是注释"),
                         ([], []))

    def test_policy_is_third_field_not_last(self):
        # 末尾的 no-resolve 是参数，不是策略；否则 DIRECT 会被读成代理
        _, blocked = deep.classify_rules("- DOMAIN-SUFFIX,anthropic.com,DIRECT,no-resolve")
        self.assertEqual(blocked, ["anthropic.com → DIRECT"])

    def test_section_is_tracked(self):
        entries = deep.classify_rule_entries(
            "prepend-rules:\n  - DOMAIN-SUFFIX,claude.ai,PROXY\n"
            "rules:\n  - DOMAIN-SUFFIX,claude.ai,DIRECT")
        self.assertEqual([e["section"] for e in entries], ["prepend", "rules"])

    def test_short_lines_ignored(self):
        # `- DOMAIN,claude.ai` 这种只有两段的写法没有策略字段，不能瞎猜
        pinned, blocked = deep.classify_rules("- DOMAIN,claude.ai")
        self.assertEqual((pinned, blocked), ([], []))

    def test_mixed_config_splits_both_ways(self):
        text = (
            "rules:\n"
            "  - DOMAIN-SUFFIX,anthropic.com,PROXY\n"
            "  - DOMAIN-SUFFIX,claude.ai,DIRECT\n"
            "  - DOMAIN-KEYWORD,claudeusercontent,REJECT\n"
            "  - DOMAIN-SUFFIX,claude.com,美国节点\n"
        )
        pinned, blocked = deep.classify_rules(text)
        self.assertEqual(len(pinned), 2)
        self.assertEqual(len(blocked), 2)

    def test_empty_text(self):
        self.assertEqual(deep.classify_rules(""), ([], []))


class PinnedVerdictTests(unittest.TestCase):
    """判定矩阵：配置、优先级、行为探测三者怎么合。"""

    REAL = {"claude.ai": "real", "api.anthropic.com": "real",
            "claudeusercontent.com": "real"}
    FAKE = {"claude.ai": "fake", "api.anthropic.com": "fake",
            "claudeusercontent.com": "fake"}

    def verdict(self, entries, scanned=True, tun=False, proxy=False, behavior=None,
                fake_route=False):
        return deep.pinned_verdict(
            entries, ["~/.config/clash/config.yaml"] if scanned else [],
            tun, proxy, behavior or self.REAL, fake_route)

    def test_direct_outranks_plain_pinned(self):
        entries = [
            {"type": "DOMAIN-SUFFIX", "payload": "anthropic.com",
             "policy": "PROXY", "section": "rules", "kind": "pinned"},
            {"type": "DOMAIN-SUFFIX", "payload": "claude.ai",
             "policy": "DIRECT", "section": "rules", "kind": "blocked"},
        ]
        self.assertEqual(self.verdict(entries)[0], "critical")

    def test_prepend_pinned_covers_plain_direct(self):
        # Clash Verge 的 prepend-rules 优先级高于订阅 rules
        entries = [
            {"type": "DOMAIN-SUFFIX", "payload": "claude.ai",
             "policy": "DIRECT", "section": "rules", "kind": "blocked"},
            {"type": "DOMAIN-SUFFIX", "payload": "claude.ai",
             "policy": "PROXY", "section": "prepend", "kind": "pinned"},
        ]
        sev, title, detail, _ = self.verdict(entries)
        self.assertEqual(sev, "pass")
        self.assertIn("置顶", title)
        self.assertIn("优先", detail)

    def test_prepend_direct_is_still_critical(self):
        entries = [
            {"type": "DOMAIN-SUFFIX", "payload": "claude.ai",
             "policy": "DIRECT", "section": "prepend", "kind": "blocked"},
            {"type": "DOMAIN-SUFFIX", "payload": "claude.ai",
             "policy": "PROXY", "section": "rules", "kind": "pinned"},
        ]
        self.assertEqual(self.verdict(entries)[0], "critical")

    def test_routed_without_rules_is_pass(self):
        self.assertEqual(self.verdict([], tun=True)[0], "pass")
        self.assertEqual(self.verdict([], proxy=True)[0], "pass")

    def test_fake_dns_without_rules_is_only_info(self):
        # fake-ip 只证明 DNS 被接管，不证明 TCP/UDP 走了同一条路
        sev, title, _, _ = self.verdict([], behavior=self.FAKE)
        self.assertEqual(sev, "info")
        self.assertIn("DNS", title)

    def test_fake_route_proves_traffic_is_tunneled(self):
        # 默认路由是 en0 时，也可能是 198.18/15 单独走 TUN
        sev, title, _, _ = self.verdict([], behavior=self.FAKE, fake_route=True)
        self.assertEqual(sev, "pass")
        self.assertIn("fake-ip 路由", title)

    def test_nothing_found_is_medium(self):
        self.assertEqual(self.verdict([])[0], "medium")

    def test_no_config_is_info(self):
        self.assertEqual(self.verdict([], scanned=False)[0], "info")


class ReachableGateTests(unittest.TestCase):
    """出口没确认时不许主动访问 claude.ai / api.anthropic.com。"""

    def run_network(self, with_network: bool, probe_result: dict):
        with mock.patch.object(scanner.netprobe, "probe", return_value=probe_result), \
             mock.patch.object(scanner, "_check_reachable",
                               side_effect=AssertionError("不该联网")):
            return scanner.check_network(with_network=with_network)

    def test_network_disabled_does_not_probe(self):
        items, info = self.run_network(False, {"available": False})
        self.assertFalse(info["available"])
        reach = next(i for i in items if i["id"] == "net.reachable")
        self.assertEqual(reach["severity"], "info")
        self.assertIn("关闭", reach["detail"])

    def test_egress_unknown_does_not_probe(self):
        items, _ = self.run_network(True, {"available": False})
        reach = next(i for i in items if i["id"] == "net.reachable")
        self.assertEqual(reach["severity"], "info")
        self.assertIn("出口", reach["detail"])


class WebRtcEvidenceTests(unittest.TestCase):
    def run_with(self, result: dict) -> dict:
        with mock.patch.object(scanner.stun, "probe", return_value=result):
            return scanner._check_webrtc("5.34.*.136")

    def base(self, **kw) -> dict:
        r = {"ips": ["112.97.32.112", "5.34.220.136"],
             "foreign": ["5.34.220.136"], "ok": True, "leak": False,
             "state": "unknown", "mask": "5.34.*.136",
             "reason": "境外节点只有一个回应，不足以判断是否分裂"}
        r.update(kw)
        return r

    def test_insufficient_evidence_is_info_not_pass(self):
        out = self.run_with(self.base())
        self.assertEqual(out["severity"], "info")
        self.assertEqual(out["title"], "UDP 出口未能判定")

    def test_split_is_high(self):
        out = self.run_with(self.base(state="leak", leak=True))
        self.assertEqual(out["severity"], "high")

    def test_all_match_is_pass(self):
        out = self.run_with(self.base(state="pass",
                                      reason="境外节点结果与基线一致"))
        self.assertEqual(out["severity"], "pass")

    def test_evidence_never_contains_a_full_ip(self):
        out = self.run_with(self.base())
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("112.97.32.112", blob)
        self.assertNotIn("5.34.220.136", blob)
        self.assertIn("112.97.*.112", blob)
        self.assertIn("5.34.*.136", blob)


class PinnedCheckTests(unittest.TestCase):
    def test_check_pinned_returns_the_consumed_id(self):
        real = {"claude.ai": "real", "api.anthropic.com": "real",
                "claudeusercontent.com": "real"}
        with mock.patch.object(deep, "_scan_rule_configs",
                               return_value=(["~/.config/clash/config.yaml"], [])), \
             mock.patch.object(deep.compat, "system_proxy",
                               return_value={"enabled": False, "pac": "", "server": ""}), \
             mock.patch.object(deep.compat, "default_route_iface",
                               return_value="en0"), \
             mock.patch.object(deep, "_dns_behavior", return_value=real):
            out = deep.check_pinned(True)
        self.assertEqual(out["id"], "net.pinned")
        self.assertEqual(out["severity"], "medium")
        self.assertEqual(out["category"], "network")

    def test_check_pinned_offline_skips_dns(self):
        with mock.patch.object(deep, "_scan_rule_configs",
                               return_value=([], [])), \
             mock.patch.object(deep.compat, "system_proxy",
                               return_value={"enabled": False, "pac": "", "server": ""}), \
             mock.patch.object(deep.compat, "default_route_iface",
                               return_value=""), \
             mock.patch.object(deep, "_resolve_all",
                               side_effect=AssertionError("关掉联网还查 DNS")):
            out = deep.check_pinned(False)
        self.assertEqual(out["id"], "net.pinned")


class AdviceConsistencyTests(unittest.TestCase):
    """同一份配置不许给出方向相反的两条建议。

    net.pinned 曾经让人「加置顶规则」，net.routing 同时让人「把 Claude 规则
    摘掉」——用户照着做完，塔还是报同一条，只会觉得在被耍。这类矛盾不会
    让任何一项变红，所以只能靠测试盯着。
    """

    SRC = (Path(__file__).resolve().parent.parent / "core/deep.py").read_text(
        encoding="utf-8")

    def test_pinned_advice_states_its_cost(self):
        for behavior in ({}, {"claude.ai": "fake"}):
            _, _, _, advice = deep.pinned_verdict([], ["~/.config/clash/x.yaml"],
                                                  False, False, behavior)
            self.assertIn("画像信号", advice, "加规则的代价没说出来")
            self.assertIn("没法同时满足", advice)

    def test_routing_never_tells_user_to_delete_pinned_rules(self):
        self.assertNotIn("把 Claude 规则从配置里摘掉", self.SRC)
        self.assertIn("不是让你把规则摘掉", self.SRC)

    def test_tun_only_does_not_claim_claude_rules_exist(self):
        # 只有 TUN 全开、配置里一处 Claude 规则都没有时，标题不能写
        # 「有针对 Claude 的规则」——那会让人去翻一个不存在的规则。
        self.assertIn("TUN 全接管，所有流量都过代理", self.SRC)
        i = self.SRC.index("def check_routing")
        body = self.SRC[i:]
        self.assertLess(body.index("if claude_rules:"), body.index("TUN 全接管"),
                        "必须先按 claude_rules 分支，再落到 TUN 文案")


class HardwareFingerprintTests(unittest.TestCase):
    """字体 / 显卡 / 虚拟机：机器本身也在说话，不只是配置文件。"""

    def setUp(self):
        self.mac = scanner.compat.IS_MAC
        scanner.compat.IS_MAC = True

    def tearDown(self):
        scanner.compat.IS_MAC = self.mac

    def with_fonts(self, hits):
        orig = scanner._font_hits
        scanner._font_hits = lambda *a, **k: hits
        try:
            return scanner._check_fonts()
        finally:
            scanner._font_hits = orig

    def test_region_fonts_are_medium(self):
        out = self.with_fonts(["simsun.ttc", "msyh.ttc"])
        self.assertEqual(out["id"], "fp.fonts")
        self.assertEqual(out["severity"], "medium")
        self.assertIn("2", out["title"])

    def test_clean_fonts_pass(self):
        out = self.with_fonts([])
        self.assertEqual(out["severity"], "pass")

    def test_region_font_list_covers_common_office_fonts(self):
        for name in ("simsun", "simhei", "msyh", "wqy", "fangsong"):
            self.assertIn(name, scanner._REGION_FONTS)

    def gpu_with(self, chip):
        orig = scanner._run
        scanner._run = lambda cmd, timeout=6.0: (
            f"Graphics/Displays:\n\n    {chip}:\n\n      Chipset Model: {chip}\n"
            "      Resolution: 1440 x 900\n")
        try:
            return scanner._check_gpu()
        finally:
            scanner._run = orig

    def test_virtual_gpu_is_flagged(self):
        for chip in ("Apple Paravirtual device", "VMware SVGA II", "llvmpipe (LLVM 15.0.7)"):
            out = self.gpu_with(chip)
            self.assertEqual(out["severity"], "medium", chip)
            self.assertIn("虚拟显卡", out["title"])

    def test_physical_gpu_passes_with_evidence(self):
        out = self.gpu_with("Apple M1 Max")
        self.assertEqual(out["severity"], "pass")
        labels = [e["label"] for e in out["evidence"]]
        self.assertIn("显卡", labels)
        self.assertIn("分辨率", labels)

    def test_unreadable_gpu_is_info_not_pass(self):
        orig = scanner._run
        scanner._run = lambda cmd, timeout=6.0: ""
        try:
            out = scanner._check_gpu()
        finally:
            scanner._run = orig
        self.assertEqual(out["severity"], "info")

    def vm_with(self, flag):
        orig = scanner._run
        def fake(cmd, timeout=6.0):
            if cmd[-1] == "kern.hv_vmm_present":
                return flag
            if cmd[-1] == "hw.model":
                return "MacBookPro18,2"
            return ""
        scanner._run = fake
        try:
            return scanner._check_vm()
        finally:
            scanner._run = orig

    def test_hypervisor_flag_is_medium(self):
        out = self.vm_with("1")
        self.assertEqual(out["id"], "fp.vm")
        self.assertEqual(out["severity"], "medium")

    def test_bare_metal_passes(self):
        out = self.vm_with("0")
        self.assertEqual(out["severity"], "pass")

    def test_non_mac_skips_instead_of_failing(self):
        scanner.compat.IS_MAC = False
        for fn in (scanner._check_fonts, scanner._check_gpu, scanner._check_vm):
            self.assertEqual(fn()["severity"], "info", fn.__name__)

    def test_new_checks_are_wired_into_level_2_1(self):
        src = (Path(__file__).resolve().parent.parent / "core/tower.py").read_text(
            encoding="utf-8")
        body = src[src.index("def _probe_identity"):]
        body = body[:body.index("\ndef ")]
        for iid in ("fp.fonts", "fp.gpu", "fp.vm"):
            self.assertIn(f'"{iid}"', body, f"{iid} 产出了但关卡没接")


class CliInstallTests(unittest.TestCase):
    """Claude Code CLI 装了几份。多份共存时「用的不是你以为的那份」。"""

    def run_with(self, which="", method="", copies=None, bundled=None,
                 version="2.0.1"):
        import shutil as _shutil
        saved = (scanner.shutil.which, scanner._cli_method, scanner._cli_version,
                 scanner._cli_copies, scanner._desktop_bundled_cli)
        scanner.shutil.which = lambda name: which if name == "claude" else ""
        scanner._cli_method = lambda real: method
        scanner._cli_version = lambda path: version
        scanner._cli_copies = lambda: dict(copies or {})
        scanner._desktop_bundled_cli = lambda: list(bundled or [])
        try:
            return scanner.check_cli()[0]
        finally:
            (scanner.shutil.which, scanner._cli_method, scanner._cli_version,
             scanner._cli_copies, scanner._desktop_bundled_cli) = saved

    def test_no_cli_is_info(self):
        out = self.run_with()
        self.assertEqual(out["id"], "cli.claude_code")
        self.assertEqual(out["severity"], "info")
        self.assertIn("没有安装", out["title"])

    def test_single_install_passes(self):
        out = self.run_with(which="/opt/homebrew/bin/claude", method="Homebrew")
        self.assertEqual(out["severity"], "pass")
        self.assertIn("2.0.1", out["title"])

    def test_path_symlink_into_npm_is_not_double_counted(self):
        """PATH 里那份就是 npm 的软链，不能算成两份。"""
        out = self.run_with(which="/usr/local/bin/claude", method="npm / bun",
                            copies={"npm": "/usr/local/lib/node_modules/@anthropic-ai/claude-code"})
        self.assertEqual(out["severity"], "pass")

    def test_two_methods_is_medium(self):
        out = self.run_with(which="/usr/local/bin/claude", method="npm / bun",
                            copies={"npm": "/usr/local/lib/node_modules/@anthropic-ai/claude-code",
                                    "brew": "/opt/homebrew/Cellar/claude-code"})
        self.assertEqual(out["severity"], "medium")
        self.assertIn("2 种", out["title"])

    def test_native_plus_brew_is_medium(self):
        out = self.run_with(which="/opt/test-home/.local/bin/claude",
                            method="native（官方安装脚本）",
                            copies={"brew": "/opt/homebrew/Cellar/claude-code"})
        self.assertEqual(out["severity"], "medium")

    def test_desktop_bundled_only_is_info(self):
        out = self.run_with(bundled=["2.0.1"])
        self.assertEqual(out["severity"], "info")
        self.assertIn("桌面版", out["title"])

    def test_desktop_bundle_alone_does_not_count_as_conflict(self):
        out = self.run_with(which="/usr/local/bin/claude", method="npm / bun",
                            bundled=["2.0.1"])
        self.assertEqual(out["severity"], "pass")

    def test_wired_into_level_2_4(self):
        src = (Path(__file__).resolve().parent.parent / "core/tower.py").read_text(
            encoding="utf-8")
        body = src[src.index("def _probe_residue"):]
        body = body[:body.index("\ndef ")]
        self.assertIn('"cli.claude_code"', body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
