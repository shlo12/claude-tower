#!/usr/bin/env python3
"""分流规则一键修复：只在临时目录里跑，不碰真实 FlClash 配置或数据库。

    python3 tools/test_proxyfix.py
"""

from __future__ import annotations

import json
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import proxyfix

def _isolate_shield_state(test, root):
    """分流修复会顺手把规则清单写给哨兵。

    这里必须把盾的状态文件也指到临时目录：否则一条普通的 apply 测试
    就会改写真实的 ~/.ccclean/shield.json。
    """
    state_dir = root / ".ccclean"
    for name, value in (("STATE_DIR", state_dir),
                        ("STATE_FILE", state_dir / "shield.json")):
        p = patch.object(proxyfix.shield_state, name, value)
        p.start()
        test.addCleanup(p.stop)
    return state_dir / "shield.json"


CONFIG = """mixed-port: 7890
proxy-groups:
  - {name: 手动选择, type: select, proxies: [自动选择]}
  - {name: Ai+, type: select, proxies: [自动选择]}
  - {name: 自动选择, type: url-test}
rules:
  - 'DOMAIN-SUFFIX,iherb.com,DIRECT'
  - 'RULE-SET,Claude,Ai+'
  - 'MATCH,手动选择'
"""


class ProxyFixTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.dir = root / "Library/Application Support/com.follow.clash"
        self.dir.mkdir(parents=True)
        self.config = self.dir / "config.yaml"
        self.db = self.dir / "database.sqlite"
        self.state = root / ".ccclean/proxyfix.json"
        self.shield_file = _isolate_shield_state(self, root)
        self.app = root / "FlClash.app"
        self.app.mkdir()
        self.config.write_text(CONFIG, encoding="utf-8")
        self._make_db()

        patches = [
            ("FLCLASH_DIR", self.dir), ("FLCLASH_CONFIG", self.config),
            ("FLCLASH_DB", self.db), ("STATE", self.state),
            ("FLCLASH_APP_CANDIDATES", (self.app,)),
            # 测试只认临时目录里的 FlClash。真实机器上同时装着 Clash Verge /
            # ClashX / Mihomo Party 时，不把这些候选清空会检测到别的客户端。
            ("VERGE_DIR_CANDIDATES", (root / "no-verge",)),
            ("VERGE_APP_CANDIDATES", (root / "NoVerge.app",)),
            ("CLASHX_DIR", root / "no-clashx"),
            ("CLASHX_CONFIGS", (root / "no-clashx/config.yaml",)),
            ("CLASHX_APP_CANDIDATES", (root / "NoClashX.app",)),
            ("MANUAL_CLIENTS", ()),
        ]
        for name, value in patches:
            p = patch.object(proxyfix, name, value)
            p.start()
            self.addCleanup(p.stop)
        for name, value in [
            ("IS_MAC", True),
            ("_proc_alive", lambda *a, **k: True),
            ("_quit", lambda: True),
            ("_launch", lambda: True),
            ("_wait_verified", lambda rules, timeout=15: True),
            ("_wait_cleared", lambda rules, timeout=15: True),
        ]:
            p = patch.object(proxyfix if name != "IS_MAC" else proxyfix.compat,
                             name, value)
            p.start()
            self.addCleanup(p.stop)

    def _make_db(self):
        con = sqlite3.connect(self.db)
        con.execute(
            'create table rules (id integer primary key, profile_id integer, '
            'rule_action text not null, content text, rule_target text, '
            'rule_provider text, sub_rule text, no_resolve integer not null default 0, '
            'src integer not null default 0, "order" text)'
        )
        con.execute(
            "insert into rules values (1, null, 'PROCESS_NAME_REGEX', "
            "'(?i).*firefox.*', 'DIRECT', null, null, 0, 0, 'a0')"
        )
        con.execute(
            "insert into rules values (2, null, 'DOMAIN_SUFFIX', "
            "'iherb.com', 'DIRECT', null, null, 0, 0, 'Zz')"
        )
        con.commit()
        con.close()

    def _rules(self):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(
                'select id, rule_action, content, rule_target, "order" '
                'from rules where profile_id is null order by "order"'
            ).fetchall()
        finally:
            con.close()

    def test_policy_follows_existing_claude_rule(self):
        target, error = proxyfix._target()
        self.assertFalse(error)
        self.assertEqual(target["policy"], "Ai+")
        self.assertEqual(len(target["rules"]), 20)

    def test_fallback_policy_when_no_claude_rule(self):
        self.config.write_text(
            "proxy-groups:\n  - {name: 全球代理, type: select}\n"
            "  - {name: 自动选择, type: url-test}\nrules:\n  - MATCH,全球代理\n",
            encoding="utf-8")
        target, error = proxyfix._target()
        self.assertFalse(error)
        self.assertEqual(target["policy"], "全球代理")

    def test_apply_inserts_only_missing_and_prepends(self):
        con = sqlite3.connect(self.db)
        con.execute(
            "insert into rules values (3, null, 'DOMAIN_SUFFIX', "
            "'claude.ai', 'Ai+', null, null, 0, 0, '1z')"
        )
        con.commit()
        con.close()

        out = proxyfix.apply("apply")
        self.assertTrue(out["verified"])
        rules = self._rules()
        ours = [r for r in rules if r[2] in proxyfix.DOMAINS + proxyfix.PORTS]
        self.assertEqual(len(ours), 20)  # 已有的 claude.ai 不重复插入
        self.assertEqual(len({r[0] for r in rules}), len(rules))
        # 新插入的规则都排在原有全局规则之前
        orders = [r[4] for r in rules]
        self.assertEqual(orders, sorted(orders))
        self.assertTrue(self.state.exists())
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertTrue(all(r[4] < "1z" for r in rules if r[0] in saved["ids"]))
        self.assertTrue(all(r[4] >= "1z" for r in rules if r[0] not in saved["ids"]))
        self.assertEqual(saved["policy"], "Ai+")
        self.assertEqual(len(saved["ids"]), 19)
        self.assertEqual({r["content"] for r in saved["before"]},
                         {"iherb.com", "claude.ai", "(?i).*firefox.*"})
        self.assertIn(proxyfix.MARK0, self.config.read_text(encoding="utf-8"))
        self.assertTrue(out["applied"])
        self.assertFalse(out["canApply"])
        # 写下的规则要记给哨兵，否则它没有可比对的清单
        guard = json.loads(self.shield_file.read_text(encoding="utf-8"))["ruleGuard"]
        self.assertEqual(guard["client"], "flclash")
        self.assertEqual(guard["path"], str(self.config))
        self.assertEqual(len(guard["rules"]), 20)
        self.assertIn("DOMAIN-SUFFIX,claude.ai", guard["rules"])
        self.assertGreater(guard["at"], 0)

        with self.assertRaises(ValueError):
            proxyfix.apply("apply")  # 未撤销前不叠加

    def test_undo_removes_only_our_rows(self):
        proxyfix.apply("apply")
        before = {r[0] for r in self._rules()}
        self.assertEqual(len(before), 22)
        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        after = self._rules()
        self.assertEqual({r[0] for r in after}, {1, 2})
        self.assertFalse(self.state.exists())
        self.assertNotIn(proxyfix.MARK0, self.config.read_text(encoding="utf-8"))
        self.assertIn("iherb.com", self.config.read_text(encoding="utf-8"))
        self.assertIn("已删除本工具写入的 20 条", out["message"])
        # 主动撤销后不能再留着清单，否则哨兵会一直报「规则不见了」
        saved = json.loads(self.shield_file.read_text(encoding="utf-8"))
        self.assertNotIn("ruleGuard", saved)

    def test_all_rules_already_present_is_noop(self):
        rules = [proxyfix._rule_text(a, p, "Ai+") for a, p in proxyfix._spec_pairs()]
        for i, rule in enumerate(rules):
            action, payload, policy = rule.split(",")
            con = sqlite3.connect(self.db)
            con.execute(
                "insert into rules values (?, null, ?, ?, ?, null, null, 0, 0, ?)",
                (100 + i, action.replace("-", "_"), payload, policy, f"0{i}z"))
            con.commit()
            con.close()
        out = proxyfix.apply("apply")
        self.assertIn("已经齐全", out["message"])
        self.assertFalse(self.state.exists())
        # 没改任何东西，但规则确实齐全——清单仍要记下来，
        # 否则哨兵会把「没修过」当成「没有可核对的规则」
        guard = json.loads(self.shield_file.read_text(encoding="utf-8"))["ruleGuard"]
        self.assertEqual(len(guard["rules"]), 20)

    def test_blocked_global_rule_refuses(self):
        con = sqlite3.connect(self.db)
        con.execute(
            "insert into rules values (9, null, 'DOMAIN_SUFFIX', "
            "'claude.ai', 'DIRECT', null, null, 0, 0, '00')"
        )
        con.commit()
        con.close()
        with self.assertRaises(ValueError) as ctx:
            proxyfix.apply("apply")
        self.assertIn("直连", str(ctx.exception))
        self.assertFalse(self.state.exists())
        self.assertEqual(len(self._rules()), 3)

    def test_quit_failure_leaves_database_untouched(self):
        with patch.object(proxyfix, "_quit", lambda: False):
            with self.assertRaises(RuntimeError):
                proxyfix.apply("apply")
        self.assertEqual(len(self._rules()), 2)
        self.assertFalse(self.state.exists())

    def test_undo_refuses_manually_edited_rule(self):
        proxyfix.apply("apply")
        con = sqlite3.connect(self.db)
        con.execute("update rules set rule_target='DIRECT' where id=(select min(id) "
                    "from rules where content='claude.ai')")
        con.commit()
        con.close()
        with self.assertRaises(ValueError):
            proxyfix.apply("undo")
        self.assertTrue(self.state.exists())

    def test_unsupported_without_flclash_files(self):
        self.db.unlink()
        out = proxyfix.status()
        self.assertFalse(out["available"])
        self.assertFalse(out["canApply"])
        self.assertIn("可修复", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_corrupt_state_blocks_apply(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text("{not json", encoding="utf-8")
        out = proxyfix.status()
        self.assertTrue(out["stateError"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_symlink_state_refused(self):
        self.state.parent.mkdir(parents=True, exist_ok=True)
        target = self.state.parent / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.state.symlink_to(target)
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_order_keys_stay_below_existing(self):
        keys = proxyfix._order_keys(16, "Zz")
        self.assertEqual(keys, sorted(keys))
        self.assertTrue(all(k < "Zz" for k in keys))
        deep = proxyfix._order_keys(16, "0z")
        self.assertTrue(all(k < "0z" for k in deep))
        self.assertEqual(len(set(deep)), 16)

    def test_config_parser_reads_injected_block(self):
        text = proxyfix._inject_rules(
            CONFIG, [proxyfix._rule_text("DOMAIN-SUFFIX", "claude.ai", "Ai+")])
        seen = proxyfix._config_rules(text)
        self.assertIn(("DOMAIN-SUFFIX", "claude.ai"), seen)
        self.assertIn(("RULE-SET", "claude"), seen)
        self.assertEqual(proxyfix._strip_marker(text), CONFIG)

    # ---------------------------------------------------------- 端口策略

    def _targets(self):
        return {(r[1].replace("_", "-").upper(), r[2]): r[3] for r in self._rules()}

    def test_reject_mode_writes_reject_for_ports_only(self):
        out = proxyfix.apply("apply", "reject")
        self.assertTrue(out["verified"])
        self.assertEqual(out["portMode"], "reject")
        targets = self._targets()
        for port in proxyfix.PORTS:
            self.assertEqual(targets[("DST-PORT", port)], "REJECT")
        for domain in proxyfix.DOMAINS:
            self.assertEqual(targets[("DOMAIN-SUFFIX", domain)], "Ai+")
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["portMode"], "reject")
        self.assertEqual(saved["policy"], "Ai+")
        # 记录里的规则文本要和数据库里实际写下去的一致，撤销才敢照它核对
        self.assertIn("DST-PORT,3478,REJECT", saved["rules"])
        self.assertIn("DOMAIN-SUFFIX,claude.ai,Ai+", saved["rules"])
        self.assertIn("REJECT", out["message"])

        # 撤销：端口指向 REJECT 是设计如此，不能当成「被手动改过」
        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        self.assertEqual({r[0] for r in self._rules()}, {1, 2})
        self.assertFalse(self.state.exists())

    def test_undo_refuses_port_rule_switched_by_hand(self):
        proxyfix.apply("apply", "reject")
        con = sqlite3.connect(self.db)
        con.execute("update rules set rule_target='Ai+' where content='3478'")
        con.commit()
        con.close()
        with self.assertRaises(ValueError):
            proxyfix.apply("undo")
        self.assertTrue(self.state.exists())

    def test_existing_reject_port_is_not_a_conflict(self):
        con = sqlite3.connect(self.db)
        con.execute(
            "insert into rules values (7, null, 'DST_PORT', '3478', 'REJECT', "
            "null, null, 0, 0, '00')"
        )
        con.commit()
        con.close()
        reject = proxyfix.status("reject")
        self.assertFalse(reject["blocked"])
        self.assertIn("DST-PORT,3478,REJECT", reject["covered"])
        self.assertEqual(len(reject["missing"]), 19)
        self.assertTrue(reject["canApply"])
        # 换成跟着代理组走，同一条 REJECT 就变成挡路的了
        proxy = proxyfix.status("proxy")
        self.assertTrue(proxy["blocked"])
        self.assertFalse(proxy["canApply"])

    def test_direct_port_rule_still_conflicts_under_reject(self):
        """端口写 DIRECT 是泄漏，选哪种策略都得拦住。"""
        con = sqlite3.connect(self.db)
        con.execute(
            "insert into rules values (8, null, 'DST_PORT', '5349', 'DIRECT', "
            "null, null, 0, 0, '00')"
        )
        con.commit()
        con.close()
        out = proxyfix.status("reject")
        self.assertTrue(out["blocked"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply", "reject")

    def test_unknown_port_mode_is_refused(self):
        # 空值等于没选，按 proxy 处理；写错的字符串必须拒绝，不能悄悄换成默认值
        for bad in ("drop", "REJECT!", "rejects", ["reject"]):
            with self.assertRaises(ValueError):
                proxyfix.apply("apply", bad)
        self.assertFalse(self.state.exists())
        self.assertEqual(len(self._rules()), 2)

    def test_old_record_without_port_mode_still_undoes(self):
        """老版本写的记录里没有 portMode，撤销不能因此失败。"""
        proxyfix.apply("apply")
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        saved.pop("portMode")
        self.state.write_text(json.dumps(saved, ensure_ascii=False), encoding="utf-8")
        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        self.assertEqual({r[0] for r in self._rules()}, {1, 2})


class _PatchMixin:
    def patch_attr(self, obj, name, value):
        p = patch.object(obj, name, value)
        p.start()
        self.addCleanup(p.stop)


VERGE_CONFIG = """mode: rule
proxy-groups:
  - {name: 手动选择, type: select, proxies: [自动选择]}
  - {name: Ai+, type: select, proxies: [自动选择]}
  - {name: 自动选择, type: url-test}
rules:
  - 'DOMAIN-SUFFIX,claude.ai,Ai+'
  - 'DOMAIN-SUFFIX,iherb.com,DIRECT'
  - 'MATCH,手动选择'
"""

VERGE_SCRIPT = """function main(config, profileName) {
  // user code: keep me
  config.dns = config.dns || {};
  return config;
}
"""


class VergeFixTests(_PatchMixin, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        self.verge = root / "Library/Application Support/Clash Verge"
        (self.verge / "profiles").mkdir(parents=True)
        (self.verge / "work").mkdir(parents=True)
        self.script = self.verge / "profiles/Script.js"
        self.script.write_text(VERGE_SCRIPT, encoding="utf-8")
        self.config = self.verge / "work/config.yaml"
        self.config.write_text(VERGE_CONFIG, encoding="utf-8")
        self.state = root / ".ccclean/proxyfix.json"
        self.shield_file = _isolate_shield_state(self, root)

        self.patch_attr(proxyfix, "VERGE_DIR_CANDIDATES", (self.verge,))
        self.patch_attr(proxyfix, "VERGE_APP_CANDIDATES", (root / "Clash Verge.app",))
        self.patch_attr(proxyfix, "STATE", self.state)
        self.patch_attr(proxyfix, "FLCLASH_CONFIG", root / "no-flclash/config.yaml")
        self.patch_attr(proxyfix, "FLCLASH_DB", root / "no-flclash/database.sqlite")
        self.patch_attr(proxyfix, "CLASHX_CONFIGS", (root / "no-clashx/config.yaml",))
        self.patch_attr(proxyfix, "MANUAL_CLIENTS", ())
        self.patch_attr(proxyfix.compat, "IS_MAC", True)
        self.patch_attr(proxyfix, "_proc_alive", lambda *a, **k: True)
        self.patch_attr(proxyfix, "_quit_verge", lambda: True)
        self.patch_attr(proxyfix, "_launch_verge", lambda: True)
        self.patch_attr(proxyfix, "_wait_verge",
                        lambda rules, present, timeout=15: True)

    def test_status_detects_verge(self):
        out = proxyfix.status()
        self.assertTrue(out["available"])
        self.assertEqual(out["client"], "Clash Verge")
        self.assertEqual(out["clientId"], "clash-verge")
        self.assertEqual(out["policy"], "Ai+")
        self.assertTrue(out["canApply"])
        self.assertEqual(len(out["rules"]), 20)
        self.assertEqual(out["scriptPath"], str(self.script).replace(str(Path.home()), "~"))

    def test_apply_prepends_and_undo_restores_exactly(self):
        out = proxyfix.apply("apply")
        self.assertTrue(out["verified"])
        text = self.script.read_text(encoding="utf-8")
        self.assertIn(proxyfix.VERGE_MARK0, text)
        self.assertIn("// user code: keep me", text)
        self.assertEqual(proxyfix._verge_strip(text), VERGE_SCRIPT)
        # 生成配置不在写入时改，改的是全局脚本
        self.assertEqual(self.config.read_text(encoding="utf-8"), VERGE_CONFIG)

        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["client"], "clash-verge")
        self.assertEqual(len(saved["rules"]), 20)
        self.assertIn(proxyfix.VERGE_MARK0, saved["block"])
        self.assertNotIn("// user code: keep me", json.dumps(saved, ensure_ascii=False))
        self.assertFalse(proxyfix.status()["canApply"])
        guard = json.loads(self.shield_file.read_text(encoding="utf-8"))["ruleGuard"]
        self.assertEqual(guard["client"], "clash-verge")
        self.assertEqual(guard["path"], str(self.script))

        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        self.assertEqual(self.script.read_text(encoding="utf-8"), VERGE_SCRIPT)
        self.assertFalse(self.state.exists())
        self.assertIn("已删除", out["message"])
        self.assertNotIn("ruleGuard",
                         json.loads(self.shield_file.read_text(encoding="utf-8")))

    def test_global_mode_needs_no_rules(self):
        self.config.write_text("mode: global\n" + VERGE_CONFIG.split("rules:")[0],
                               encoding="utf-8")
        out = proxyfix.status()
        self.assertFalse(out["canApply"])
        self.assertIn("全局", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_missing_script_explains_how_to_enable(self):
        self.script.unlink()
        out = proxyfix.status()
        self.assertFalse(out["available"])
        self.assertIn("Script.js", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_unrecognized_main_is_refused(self):
        broken = "function main(config) { return config }\n"
        self.script.write_text(broken, encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            proxyfix.apply("apply")
        self.assertIn("结构不认识", str(ctx.exception))
        self.assertEqual(self.script.read_text(encoding="utf-8"), broken)
        self.assertFalse(self.state.exists())

    def test_unrecorded_block_is_refused(self):
        injected = proxyfix._verge_inject(
            VERGE_SCRIPT, [proxyfix._rule_text(a, p, "Ai+") for a, p in proxyfix._spec_pairs()])
        self.script.write_text(injected, encoding="utf-8")
        out = proxyfix.status()
        self.assertFalse(out["canApply"])
        self.assertIn("没有撤销记录", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_undo_refuses_edited_block(self):
        proxyfix.apply("apply")
        text = self.script.read_text(encoding="utf-8")
        self.script.write_text(
            text.replace('"DOMAIN-SUFFIX,claude.ai,Ai+"',
                         '"DOMAIN-SUFFIX,claude.ai,DIRECT"'),
            encoding="utf-8")
        with self.assertRaises(ValueError):
            proxyfix.apply("undo")
        self.assertTrue(self.state.exists())

    def test_reject_mode_writes_reject_into_script_block(self):
        out = proxyfix.apply("apply", "reject")
        self.assertTrue(out["verified"])
        text = self.script.read_text(encoding="utf-8")
        self.assertIn("DST-PORT,3478,REJECT", text)
        self.assertIn("DOMAIN-SUFFIX,claude.ai,Ai+", text)
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["portMode"], "reject")
        self.assertEqual(saved["policy"], "Ai+")
        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        self.assertEqual(self.script.read_text(encoding="utf-8"), VERGE_SCRIPT)


class ClashXFixTests(_PatchMixin, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        self.dir = root / ".config/clash"
        self.dir.mkdir(parents=True)
        self.config = self.dir / "config.yaml"
        self.config.write_text(VERGE_CONFIG, encoding="utf-8")
        self.state = root / ".ccclean/proxyfix.json"
        self.shield_file = _isolate_shield_state(self, root)

        self.patch_attr(proxyfix, "CLASHX_DIR", self.dir)
        self.patch_attr(proxyfix, "CLASHX_CONFIGS", (self.config,))
        self.patch_attr(proxyfix, "CLASHX_APP_CANDIDATES", (root / "ClashX.app",))
        self.patch_attr(proxyfix, "STATE", self.state)
        self.patch_attr(proxyfix, "FLCLASH_CONFIG", root / "no-flclash/config.yaml")
        self.patch_attr(proxyfix, "FLCLASH_DB", root / "no-flclash/database.sqlite")
        self.patch_attr(proxyfix, "VERGE_DIR_CANDIDATES", ())
        self.patch_attr(proxyfix, "MANUAL_CLIENTS", ())
        self.patch_attr(proxyfix.compat, "IS_MAC", True)
        self.patch_attr(proxyfix, "_proc_alive", lambda *a, **k: True)
        self.patch_attr(proxyfix, "_quit_clashx", lambda: True)
        self.patch_attr(proxyfix, "_launch_clashx", lambda: True)
        self.patch_attr(proxyfix, "_wait_clashx",
                        lambda rules, present, timeout=15: True)

    def test_apply_prepends_and_undo_restores_exactly(self):
        out = proxyfix.apply("apply")
        self.assertTrue(out["verified"])
        text = self.config.read_text(encoding="utf-8")
        self.assertIn(proxyfix.MARK0, text)
        self.assertEqual(proxyfix._strip_marker(text), VERGE_CONFIG)
        # 规则块必须在已有规则之前，否则会被 MATCH 截走
        self.assertLess(text.index(proxyfix.MARK0), text.index("iherb.com"))
        saved = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertEqual(saved["client"], "clashx")
        self.assertNotIn("iherb.com", json.dumps(saved, ensure_ascii=False))
        guard = json.loads(self.shield_file.read_text(encoding="utf-8"))["ruleGuard"]
        self.assertEqual(guard["client"], "clashx")
        self.assertEqual(guard["path"], str(self.config))

        out = proxyfix.apply("undo")
        self.assertTrue(out["verified"])
        self.assertEqual(self.config.read_text(encoding="utf-8"), VERGE_CONFIG)
        self.assertFalse(self.state.exists())
        self.assertNotIn("ruleGuard",
                         json.loads(self.shield_file.read_text(encoding="utf-8")))

    def test_symlink_config_is_refused(self):
        target = self.root / "real.yaml"
        target.write_text(VERGE_CONFIG, encoding="utf-8")
        self.config.unlink()
        self.config.symlink_to(target)
        out = proxyfix.status()
        self.assertFalse(out["available"])
        self.assertIn("符号链接", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_config_without_rules_is_refused(self):
        self.config.write_text("mixed-port: 7890\n", encoding="utf-8")
        out = proxyfix.status()
        self.assertFalse(out["available"])
        self.assertIn("proxy-groups", out["reason"])

    def test_global_mode_needs_no_rules(self):
        self.config.write_text("mode: global\n" + VERGE_CONFIG.split("rules:")[0],
                               encoding="utf-8")
        out = proxyfix.status()
        self.assertFalse(out["canApply"])
        self.assertIn("全局", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_unrecorded_block_is_refused(self):
        rules = [proxyfix._rule_text(a, p, "Ai+") for a, p in proxyfix._spec_pairs()]
        self.config.write_text(proxyfix._inject_rules(VERGE_CONFIG, rules),
                               encoding="utf-8")
        out = proxyfix.status()
        self.assertFalse(out["canApply"])
        self.assertIn("没有撤销记录", out["reason"])
        with self.assertRaises(ValueError):
            proxyfix.apply("apply")

    def test_reject_port_rule_counts_as_covered_under_reject(self):
        """已经写成 REJECT 的端口，在「直接拒绝」下是达标，不是冲突。"""
        text = VERGE_CONFIG.replace(
            "  - 'DOMAIN-SUFFIX,iherb.com,DIRECT'",
            "  - 'DST-PORT,3478,REJECT'\n  - 'DOMAIN-SUFFIX,iherb.com,DIRECT'")
        self.config.write_text(text, encoding="utf-8")
        reject = proxyfix.status("reject")
        self.assertIn("DST-PORT,3478,REJECT", reject["covered"])
        self.assertNotIn("DST-PORT,3478,REJECT", reject["missing"])
        # 换回「跟着代理组走」，同一条就得补上（按要写的策略渲染）
        proxy = proxyfix.status("proxy")
        self.assertIn("DST-PORT,3478,Ai+", proxy["missing"])


class ManualClientTests(_PatchMixin, unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.app = root / "Shadowrocket.app"
        self.app.mkdir()
        self.state = root / ".ccclean/proxyfix.json"
        self.shield_file = _isolate_shield_state(self, root)
        self.patch_attr(proxyfix, "MANUAL_CLIENTS", ({
            "id": "shadowrocket", "name": "Shadowrocket",
            "apps": (self.app,), "proc": "/Shadowrocket.app/Contents/MacOS/",
            "guidance": ("去应用里编辑规则。", "把 Claude 域名放最上面。"),
        },))
        self.patch_attr(proxyfix, "STATE", self.state)
        self.patch_attr(proxyfix, "FLCLASH_CONFIG", root / "no-flclash/config.yaml")
        self.patch_attr(proxyfix, "FLCLASH_DB", root / "no-flclash/database.sqlite")
        self.patch_attr(proxyfix, "VERGE_DIR_CANDIDATES", ())
        self.patch_attr(proxyfix, "CLASHX_CONFIGS", (root / "no-clashx/config.yaml",))
        self.patch_attr(proxyfix.compat, "IS_MAC", True)
        self.patch_attr(proxyfix, "_proc_alive", lambda *a, **k: True)

    def test_manual_client_is_detected_but_not_rewritten(self):
        out = proxyfix.status()
        self.assertFalse(out["available"])
        self.assertTrue(out["manual"])
        self.assertEqual(out["client"], "Shadowrocket")
        self.assertTrue(out["guidance"])
        self.assertFalse(out["canApply"])
        with self.assertRaises(ValueError) as ctx:
            proxyfix.apply("apply")
        self.assertIn("手动", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
