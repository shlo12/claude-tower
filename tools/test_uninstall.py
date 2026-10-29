#!/usr/bin/env python3
"""卸载器：清单完整性、执行顺序、废纸篓语义。

这个模块是唯一会删用户东西的地方，所以测试的重点不是「功能对不对」，
而是「最坏情况下会不会删错」：

  * 确认串不对 → 一行都不执行
  * 顺序错了 → 记录先没了，撤销依据也就没了
  * 用 rm 而不是废纸篓 → 删错了找不回来

**隔离是在模块级做的，不是在每个测试类里。** 这里踩过一次：
只给「执行类」的测试打了桩，另一个类里的 `execute()` 拿着真实路径
跑了一次，把开发机上的 `~/.ccclean` 整个移进了废纸篓。凡是要碰
`execute()` 的测试，路径必须在这个文件被 import 之后就已经换掉。

    python3 tools/test_uninstall.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import uninstall as U  # noqa: E402

# 整个模块共用的沙箱。setUpModule 之前不会有任何测试跑起来，
# 所以不存在「还没来得及打桩」的窗口。
_SANDBOX: dict = {}


def setUpModule():
    tmp = tempfile.TemporaryDirectory()
    base = Path(tmp.name)
    trash = base / "trash"
    trash.mkdir()
    _SANDBOX.update(
        tmp=tmp,
        base=base,
        trash=trash,
        saved=(U.STATE_DIR, U.RUNTIME_DIR, U.TOWER_APP_PATHS, U.compat.send_to_trash),
    )
    U.STATE_DIR = base / ".ccclean"
    U.RUNTIME_DIR = base / "runtime"
    # 应用包也指到沙箱里：免得测试去量真实应用包的体积、更免得动到它
    U.TOWER_APP_PATHS = (base / "Claude Tower.app",)

    def fake_trash(path):
        src = Path(path)
        _SANDBOX.setdefault("calls", []).append(src)
        # 每次都换个新名字：同一个测试文件里会反复「删」同名目录，
        # 用「存在就加后缀」的写法迟早撞名（rename 到非空目录直接 ENOTEMPTY）
        _SANDBOX["seq"] = _SANDBOX.get("seq", 0) + 1
        dest = trash / f"{_SANDBOX['seq']:03d}-{src.name}"
        os.rename(src, dest)
        return True, str(dest)

    U.compat.send_to_trash = fake_trash


def tearDownModule():
    (U.STATE_DIR, U.RUNTIME_DIR, U.TOWER_APP_PATHS,
     U.compat.send_to_trash) = _SANDBOX["saved"]
    _SANDBOX["tmp"].cleanup()


def _trashed(name: str) -> Path | None:
    """在沙箱废纸篓里找最近一次被移进去的那个名字。"""
    hits = sorted(_SANDBOX["trash"].glob(f"*-{name}"))
    return hits[-1] if hits else None


def _make_dirs() -> None:
    """每个执行类测试都从「有东西可删」的状态开始。"""
    U.STATE_DIR.mkdir(parents=True, exist_ok=True)
    (U.STATE_DIR / "tower.json").write_text("{}", encoding="utf-8")
    U.RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    (U.RUNTIME_DIR / "cache.bin").write_bytes(b"x" * 128)


class PlanShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # plan() 会去量目录体积、读三个模块的状态，一次就够
        cls.plan = U.plan()

    def test_has_all_items(self):
        ids = [i["id"] for i in self.plan["items"]]
        self.assertEqual(sorted(ids), sorted(U._ORDER))

    def test_ids_unique(self):
        ids = [i["id"] for i in self.plan["items"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_items_sorted_like_execution_order(self):
        # 清单顺序就是执行顺序：用户看到的顺序必须和实际发生的顺序一致
        self.assertEqual([i["id"] for i in self.plan["items"]], U._ORDER)

    def test_required_fields(self):
        for item in self.plan["items"]:
            for key in ("id", "title", "paths", "size", "sizeText",
                        "default", "available", "kind", "why", "danger"):
                self.assertIn(key, item, item["id"])
            self.assertIsInstance(item["paths"], list)
            self.assertIsInstance(item["default"], bool)
            self.assertIsInstance(item["available"], bool)
            self.assertTrue(item["why"], item["id"])
            self.assertTrue(item["danger"], item["id"])

    def test_confirm_word_is_explicit(self):
        self.assertEqual(self.plan["confirmWord"], "UNINSTALL")

    def test_total_matches_sum(self):
        self.assertEqual(self.plan["totalBytes"], sum(i["size"] for i in self.plan["items"]))

    def test_warnings_exist(self):
        self.assertTrue(self.plan["warnings"])

    def test_unavailable_items_are_not_default_checked(self):
        # 没有的东西不该默认勾上：勾了就是在骗用户「这里有一坨要删」
        for item in self.plan["items"]:
            if not item["available"]:
                self.assertFalse(item["default"], item["id"])


class OrderTests(unittest.TestCase):
    """顺序是这个模块最容易改坏、也最贵的地方。"""

    def test_tower_app_is_last(self):
        self.assertEqual(U._ORDER[-1], "tower_app")

    def test_reverts_before_state(self):
        # proxyfix 把「写过哪几行」记在 ~/.ccclean/proxyfix.json 里
        self.assertLess(U._ORDER.index("proxyfix"), U._ORDER.index("state"))
        self.assertLess(U._ORDER.index("privacy"), U._ORDER.index("state"))
        self.assertLess(U._ORDER.index("ipv6"), U._ORDER.index("state"))

    def test_stop_before_delete(self):
        # 哨兵还在跑的时候删文件，会被看门狗拉起来再写一遍
        self.assertLess(U._ORDER.index("stop"), U._ORDER.index("launchagent"))
        self.assertLess(U._ORDER.index("stop"), U._ORDER.index("state"))

    def test_bundled_shield_is_not_a_separate_item(self):
        # 哨兵嵌在塔的 Resources 里，清单上再列一项就成了「删了塔还留着哨兵」
        self.assertNotIn("shield_app", U._ORDER)
        src = (ROOT / "core/uninstall.py").read_text(encoding="utf-8")
        self.assertIn("Resources 里", src)


class ConfirmTests(unittest.TestCase):
    def test_wrong_word_rejected(self):
        for bad in ("", "DELETE", "UNINSTAL", "y", "uninstall!"):
            with self.assertRaises(ValueError, msg=bad):
                U.execute(["state"], bad)

    def test_whitespace_and_case_tolerated(self):
        # 大小写和首尾空格不算「说错了」——那不是安全边界，是手滑。
        _make_dirs()
        with self.assertRaises(ValueError) as ctx:
            U.execute([], "  uninstall ")
        # 报的应该是「没勾选」，说明确认串这一关已经过了
        self.assertIn("没有勾选", str(ctx.exception))

    def test_empty_ids_rejected(self):
        with self.assertRaises(ValueError):
            U.execute([], "UNINSTALL")

    def test_unknown_ids_ignored(self):
        with self.assertRaises(ValueError):
            U.execute(["not-a-real-item"], "UNINSTALL")


class ExecuteTests(unittest.TestCase):
    def setUp(self):
        _make_dirs()
        _SANDBOX["calls"] = []

    def test_state_moves_to_trash_not_rm(self):
        res = U.execute(["state"], "UNINSTALL")
        row = next(r for r in res["results"] if r["id"] == "state")
        self.assertTrue(row["ok"], row)
        self.assertFalse(U.STATE_DIR.exists())
        moved = _trashed(".ccclean")
        self.assertIsNotNone(moved, "状态目录应当出现在废纸篓里")
        self.assertTrue((moved / "tower.json").exists(), "内容应当完整地躺在废纸篓里")
        self.assertIn(U.STATE_DIR, _SANDBOX["calls"])

    def test_runtime_moves_to_trash(self):
        U.execute(["runtime"], "UNINSTALL")
        self.assertFalse(U.RUNTIME_DIR.exists())
        self.assertIsNotNone(_trashed("runtime"))

    def test_execution_follows_fixed_order(self):
        # 故意反着传：执行顺序必须按 _ORDER 走，不按用户传的顺序
        res = U.execute(["runtime", "state"], "UNINSTALL")
        self.assertEqual([r["id"] for r in res["results"]], ["state", "runtime"])

    def test_missing_dir_is_ok_not_error(self):
        res = U.execute(["runtime"], "UNINSTALL")
        self.assertTrue(next(r for r in res["results"] if r["id"] == "runtime")["ok"])
        # 再跑一次：目录已经没了，应当报「跳过」而不是失败
        row2 = U.execute(["runtime"], "UNINSTALL")["results"][0]
        self.assertTrue(row2["ok"])
        self.assertIn("跳过", row2["message"])

    def test_quit_only_when_tower_app_selected(self):
        self.assertFalse(U.execute(["state"], "UNINSTALL")["quit"])

    def test_single_failure_does_not_stop_the_rest(self):
        def boom(_path):
            raise OSError("磁盘满了")

        saved = U.compat.send_to_trash
        U.compat.send_to_trash = boom
        try:
            res = U.execute(["state", "runtime"], "UNINSTALL")
        finally:
            U.compat.send_to_trash = saved
        self.assertEqual(len(res["results"]), 2)
        self.assertFalse(any(r["ok"] for r in res["results"]))

    def test_leftovers_after_delete(self):
        U.execute(["state", "runtime"], "UNINSTALL")
        left = U.leftovers()
        self.assertFalse(any(str(U.STATE_DIR) in x for x in left))

    def test_removing_tower_bundle_takes_sentry_with_it(self):
        app = U.TOWER_APP_PATHS[0]
        nested = app / "Contents" / "Resources" / "Claude Shield.app" / "Contents" / "MacOS"
        nested.mkdir(parents=True)
        (nested / "Shield").write_text("x", encoding="utf-8")
        row = U.execute(["tower_app"], "UNINSTALL")["results"][0]
        self.assertTrue(row["ok"], row)
        self.assertFalse(app.exists())
        moved = _trashed("Claude Tower.app")
        self.assertIsNotNone(moved)
        self.assertTrue((moved / "Contents" / "Resources" / "Claude Shield.app" / "Contents"
                         / "MacOS" / "Shield").exists())


class SizeTests(unittest.TestCase):
    def test_size_of_missing_path(self):
        self.assertEqual(U._size(Path("/nonexistent-ccclean-test")), 0)

    def test_size_text(self):
        self.assertEqual(U._size_text(0), "0 B")
        self.assertEqual(U._size_text(512), "512 B")
        self.assertEqual(U._size_text(2048), "2 KB")
        self.assertIn("MB", U._size_text(5 * 1024 * 1024))

    def test_display_shortens_home(self):
        self.assertTrue(U._display(Path.home() / "x").startswith("~"))


class ModuleStepTests(unittest.TestCase):
    """privacy / ipv6 / proxyfix 真的执行一次，但把副作用换成假的。

    这三项会改 hosts、系统网络设置和代理客户端配置，测试绝不能碰真东西；
    可「一次都不跑」也不对——顺序和参数传错了，只有跑一次才看得见。
    """

    def setUp(self):
        _make_dirs()
        self.saved = {n: getattr(U, n).apply
                      for n in ("privacy", "ipv6cfg", "proxyfix")}
        self.calls = []

    def tearDown(self):
        for name, fn in self.saved.items():
            getattr(U, name).apply = fn

    def _fake(self, name, result):
        def call(arg):
            self.calls.append((name, arg))
            return result
        getattr(U, name).apply = call

    def test_privacy_restores_with_false(self):
        self._fake("privacy", {"ok": True, "message": "已恢复"})
        row = U.execute(["privacy"], "UNINSTALL")["results"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(self.calls, [("privacy", False)])

    def test_ipv6_restores(self):
        self._fake("ipv6cfg", {"ok": True, "message": "已恢复为 Automatic"})
        row = U.execute(["ipv6"], "UNINSTALL")["results"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(self.calls, [("ipv6cfg", "restore")])

    def test_proxyfix_undoes(self):
        self._fake("proxyfix", {"ok": True, "message": "已撤销"})
        row = U.execute(["proxyfix"], "UNINSTALL")["results"][0]
        self.assertTrue(row["ok"])
        self.assertEqual(self.calls, [("proxyfix", "undo")])

    def test_module_failure_is_reported_not_raised(self):
        self._fake("ipv6cfg", {"ok": False, "message": "没有权限"})
        row = U.execute(["ipv6"], "UNINSTALL")["results"][0]
        self.assertFalse(row["ok"])
        self.assertIn("没有权限", row["message"])

    def test_stop_uses_identity_and_watchdog_goes_first(self):
        calls = []

        def fake_stop(patterns, accept=None):
            calls.append((patterns, accept))
            return 1, []

        saved = U._stop
        old_mac = U.compat.IS_MAC
        U._stop = fake_stop
        U.compat.IS_MAC = True
        try:
            row = U._run_one("stop", {"title": "停止看门狗与哨兵"})
        finally:
            U._stop = saved
            U.compat.IS_MAC = old_mac
        self.assertTrue(row["ok"])
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0][1], U._is_watchdog)
        self.assertIs(calls[1][1], U._is_shield)
        self.assertIn("Claude Shield.app", calls[1][0][0])


class IdentityTests(unittest.TestCase):
    """kill 之前先认人：pgrep 匹配的是命令行，不是身份。"""

    def test_watchdog_identity(self):
        good = "/Applications/Claude Shield.app/Contents/MacOS/ShieldWatchdog"
        self.assertTrue(U._is_watchdog(good))
        self.assertFalse(U._is_watchdog("/usr/bin/python3"))
        self.assertFalse(U._is_watchdog("/tmp/ShieldWatchdog"))

    def test_shield_identity_requires_bundle(self):
        self.assertTrue(U._is_shield(
            "/Applications/Claude Shield.app/Contents/MacOS/Shield"))
        self.assertFalse(U._is_shield("/opt/tools/Shield"))
        self.assertFalse(U._is_shield(
            "/Applications/Claude Shield.app/Contents/MacOS/ShieldWatchdog"))

    def test_exec_path_of_self_is_readable(self):
        self.assertTrue(U._exec_path(os.getpid()))

    def test_pgrep_match_without_identity_is_filtered(self):
        # 起一个命令行里带标记、但不是哨兵的进程
        marker = f"ccclean-identity-{os.getpid()}"
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)", marker])
        try:
            self.assertTrue(U._pids(marker), "pgrep 应当先匹配到它")
            self.assertEqual(U._pids(marker, U._is_watchdog), [],
                             "身份不对的进程必须被过滤掉")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class PlanPrivacyPathsTests(unittest.TestCase):
    def test_privacy_lists_hosts_as_well(self):
        saved = U.privacy.status
        U.privacy.status = lambda: {"restoreAvailable": True,
                                    "configPath": "~/.claude/settings.json"}
        try:
            item = next(i for i in U.plan()["items"] if i["id"] == "privacy")
        finally:
            U.privacy.status = saved
        self.assertIn("/etc/hosts", item["paths"])
        self.assertIn("~/.claude/settings.json", item["paths"])


class SafetyTests(unittest.TestCase):
    def test_no_recursive_rm_in_source(self):
        src = (ROOT / "core/uninstall.py").read_text(encoding="utf-8")
        self.assertNotIn("shutil.rmtree", src)
        self.assertNotIn("rm -rf", src)
        self.assertNotIn(".unlink()", src.split("def execute", 1)[-1])

    def test_never_targets_home_itself(self):
        for item in U.plan()["items"]:
            for path in item["paths"]:
                self.assertNotEqual(str(path).rstrip("/"), str(Path.home()).rstrip("/"),
                                    item["id"])

    def test_warning_matches_what_it_actually_touches(self):
        # privacy 这一项会恢复 ~/.claude/settings.json 和 /etc/hosts，
        # 文案不能反过来说「不动 ~/.claude 里的配置」。
        src = (ROOT / "core/uninstall.py").read_text(encoding="utf-8")
        self.assertNotIn("不会动你的 Claude Code 本身、~/.claude 里的配置", src)
        self.assertIn("本工具没改过的内容", src)
        self.assertIn("/etc/hosts", src)

    def test_kill_excludes_self(self):
        src = (ROOT / "core/uninstall.py").read_text(encoding="utf-8")
        self.assertIn("p != os.getpid()", src)

    def test_module_isolation_is_active(self):
        """这条是给未来的自己看的：上面那次事故就发生在这条断言缺失的时候。"""
        self.assertNotEqual(U.STATE_DIR, Path.home() / ".ccclean")
        self.assertIn(str(_SANDBOX["base"]), str(U.STATE_DIR))


if __name__ == "__main__":
    unittest.main(verbosity=2)
