#!/usr/bin/env python3
"""自动更新的离线检查。

不连 GitHub：起一个本地 HTTP 服务器冒充 Releases API，更新包也是
当场用 zipfile 拼出来的。`codesign` 用一个只拦它自己的假 run 替代——
真去签名假包既慢又不稳定，而「签名不过必须拒绝」这件事单独有用例。

现在只有一个包：Claude Shield.app 嵌在 Claude Tower.app 的 Resources 里。
所有状态写在临时 HOME 下，跑完不影响 ~/.ccclean。
"""
from __future__ import annotations

import hashlib
import http.server
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HOME = Path(tempfile.mkdtemp(prefix="ccclean-update-home-"))
os.environ["HOME"] = str(HOME)
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core import updater  # noqa: E402

REAL_RUN = subprocess.run
CODESIGN = {"rc": 0}


def fake_run(cmd, *args, **kwargs):
    if cmd[:1] == ["codesign"]:
        return subprocess.CompletedProcess(cmd, CODESIGN["rc"], "", "")
    return REAL_RUN(cmd, *args, **kwargs)


def bundle_zip(app_name: str, bundle_id: str, version: str, exe: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        plist = {
            "CFBundleIdentifier": bundle_id,
            "CFBundleShortVersionString": version,
            "CFBundleExecutable": exe,
        }
        zf.writestr(f"{app_name}/Contents/Info.plist", plistlib.dumps(plist))
        info = zipfile.ZipInfo(f"{app_name}/Contents/MacOS/{exe}")
        info.external_attr = (0o100755 << 16)
        zf.writestr(info, b"#!/bin/sh\nexit 0\n")
    return buf.getvalue()


def tower_zip(version: str, shield_version: str) -> bytes:
    """一个完整的塔包：塔本体 + Resources 里嵌着的哨兵。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        tower_plist = {
            "CFBundleIdentifier": updater.TOWER_BUNDLE_ID,
            "CFBundleShortVersionString": version,
            "CFBundleExecutable": "CCclean",
        }
        zf.writestr("Claude Tower.app/Contents/Info.plist", plistlib.dumps(tower_plist))
        exe = zipfile.ZipInfo("Claude Tower.app/Contents/MacOS/CCclean")
        exe.external_attr = (0o100755 << 16)
        zf.writestr(exe, b"#!/bin/sh\nexit 0\n")
        shield_plist = {
            "CFBundleIdentifier": updater.SHIELD_BUNDLE_ID,
            "CFBundleShortVersionString": shield_version,
            "CFBundleExecutable": "Shield",
        }
        zf.writestr("Claude Tower.app/Contents/Resources/Claude Shield.app/Contents/Info.plist",
                    plistlib.dumps(shield_plist))
        sexe = zipfile.ZipInfo(
            "Claude Tower.app/Contents/Resources/Claude Shield.app/Contents/MacOS/Shield")
        sexe.external_attr = (0o100755 << 16)
        zf.writestr(sexe, b"#!/bin/sh\nexit 0\n")
    return buf.getvalue()


def write_bundle(path: Path, bundle_id: str, version: str, exe: str) -> Path:
    macos = path / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    plist = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": version,
        "CFBundleExecutable": exe,
    }
    (path / "Contents" / "Info.plist").write_bytes(plistlib.dumps(plist))
    exe_path = macos / exe
    exe_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe_path.chmod(0o755)
    return path


def sign_bundle(path: Path) -> None:
    # setUp 会把 subprocess.run 换成只拦 codesign 的假实现；这里必须
    # 用真 run，否则「真签名过的包」其实一根签名都没有。
    REAL_RUN(["codesign", "--force", "--deep", "--sign", "-", str(path)],
             check=True, capture_output=True)


def real_bundle(path: Path, bundle_id: str, version: str, exe: str) -> Path:
    """落一个真能被 codesign 验过的 .app，用来跑安装脚本本体。"""
    write_bundle(path, bundle_id, version, exe)
    sign_bundle(path)
    return path


def real_tower(path: Path, version: str, shield_version: str) -> Path:
    """哨兵要先写进去再签外层：先签塔、后加资源会让外层签名当场失效。"""
    write_bundle(path, updater.TOWER_BUNDLE_ID, version, "CCclean")
    write_bundle(updater.nested_shield(path), updater.SHIELD_BUNDLE_ID,
                 shield_version, "Shield")
    sign_bundle(path)
    return path


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    server_version = "FakeGitHub"

    def do_GET(self):
        self.server.hits.append(self.path)
        if self.path == "/redirect-away":
            self.send_response(302)
            self.send_header("Location", "http://evil.example/x")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = self.server.routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class UpdaterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
        cls.server.routes = {}
        cls.server.hits = []
        cls.port = cls.server.server_port
        cls.base = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.saved_api = updater.GITHUB_API
        updater.GITHUB_API = cls.base

    @classmethod
    def tearDownClass(cls):
        updater.GITHUB_API = cls.saved_api
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(HOME, ignore_errors=True)

    def setUp(self):
        updater.subprocess.run = fake_run
        CODESIGN["rc"] = 0
        # 测试机器上可能真有一个哨兵在跑。安装脚本现在会按 pid 停掉它，
        # 这里必须断开这条线，否则跑一次测试就把用户的哨兵杀了。
        self._real_shield_running = updater._shield_running
        self._real_shield_pid = updater._shield_pid
        updater._shield_running = lambda: False
        updater._shield_pid = lambda: None
        shutil.rmtree(updater.STATE_DIR, ignore_errors=True)
        updater.STATE_DIR.mkdir(parents=True)
        self.server.routes.clear()
        self.server.hits.clear()
        self.tower_zip = tower_zip("2.0.0", "1.5.0")
        self.release("/tower.zip", self.tower_zip)
        self.publish()

    def tearDown(self):
        updater.subprocess.run = REAL_RUN
        updater._shield_running = self._real_shield_running
        updater._shield_pid = self._real_shield_pid
        # 真脚本用例失败时可能留下 active 标记，别让后续用例跟着一起挂
        shutil.rmtree(updater.RUN_DIR, ignore_errors=True)
        updater.configure("", auto_check=True)

    # ---- 造数据 ----

    def release(self, path: str, data: bytes):
        self.server.routes[path] = data

    def publish(self, *, version="2.0.0", shield="1.5.0", min_os="11.0",
                tag=None, prerelease=False, tower=None,
                manifest_extra=None):
        tower = tower if tower is not None else self.tower_zip
        manifest = {
            "schema": 1,
            "version": version,
            "shieldVersion": shield,
            "minMacOS": min_os,
            "notes": "测试版本",
            "assets": {
                "tower": {"name": "ClaudeTower.zip", "bytes": len(tower),
                          "sha256": hashlib.sha256(tower).hexdigest()},
            },
        }
        if manifest_extra:
            manifest.update(manifest_extra)
        self.release("/update-manifest.json", json.dumps(manifest).encode())
        release = {
            "tag_name": tag or f"v{version}",
            "draft": False,
            "prerelease": prerelease,
            "body": "发布说明",
            "html_url": "https://github.com/o/r/releases/latest",
            "assets": [
                {"name": "update-manifest.json", "size": len(json.dumps(manifest)),
                 "browser_download_url": f"{self.base}/update-manifest.json"},
                {"name": "ClaudeTower.zip", "size": len(tower),
                 "browser_download_url": f"{self.base}/tower.zip"},
            ],
        }
        self.release("/repos/o/r/releases/latest", json.dumps(release).encode())

    # ---- 检查 ----

    def test_unconfigured_never_touches_network(self):
        result = updater.check(force=True, current_tower="1.0.0")
        self.assertEqual(result["status"], "unconfigured")
        self.assertEqual(self.server.hits, [])
        state = updater.status("1.0.0", "1.0.0")
        self.assertEqual(state["state"], "unconfigured")
        self.assertFalse(state["stagedReady"])
        self.assertFalse(updater.auto_maybe("1.0.0"))

    def test_check_finds_tower_update(self):
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="1.9.0", current_shield="1.4.0")
        self.assertTrue(result["newer"])
        self.assertEqual(result["latest"]["version"], "2.0.0")
        self.assertEqual(result["latest"]["shieldVersion"], "1.5.0")
        state = updater.status("1.9.0", "1.4.0")
        self.assertEqual(state["state"], "update")

    def test_same_tower_version_is_current_even_if_manifest_shield_newer(self):
        """更新单位是整个包：塔没变就没有东西可装，不再单独比哨兵版本。"""
        self.publish(shield="9.9.9")
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="2.0.0", current_shield="1.5.0")
        self.assertFalse(result["newer"])

    def test_same_versions_means_current(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="2.0.0", current_shield="1.5.0")
        state = updater.status("2.0.0", "1.5.0")
        self.assertEqual(state["state"], "current")
        self.assertFalse(state["newer"])

    def test_prerelease_is_rejected(self):
        self.publish(prerelease=True)
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="1.0.0")
        self.assertFalse(result["ok"])
        self.assertIn("Release", result["error"])

    def test_min_macos_too_new_is_rejected(self):
        self.publish(min_os="99.0")
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="1.0.0")
        self.assertFalse(result["ok"])
        self.assertIn("99.0", result["error"])

    def test_repo_change_drops_previous_verdict(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        updater.download(current_tower="1.0.0")
        self.assertIsNotNone(updater.load().get("staged"))
        updater.configure("other/repo")
        data = updater.load()
        self.assertIsNone(data.get("latest"))
        self.assertIsNone(data.get("staged"))
        self.assertEqual(data["repo"], "other/repo")

    def test_shield_not_installed_does_not_pin_update(self):
        """没装哨兵时不能因为「空串比谁都旧」把更新提示永远亮着。"""
        self.publish(shield="1.5.0")
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="2.0.0", current_shield="")
        self.assertFalse(result["newer"])
        self.assertEqual(updater.status("2.0.0", "")["state"], "current")

    def test_os_version_accepts_two_components(self):
        self.assertEqual(updater._os_ver("11.0"), (11, 0, 0))
        self.assertEqual(updater._os_ver("14"), (14, 0, 0))
        self.assertIsNone(updater._os_ver("eleven"))
        self.assertTrue(updater._os_ok("11.0"))

    # ---- 下载与校验 ----

    def test_download_stages_nested_app_and_restores_exec_bits(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        result = updater.download(current_tower="1.0.0", current_shield="1.0.0")
        self.assertTrue(result["ok"])
        staged = updater._staged_path("2.0.0")
        tower_exe = staged / "tower" / "Claude Tower.app" / "Contents" / "MacOS" / "CCclean"
        shield_exe = (staged / "tower" / "Claude Tower.app" / "Contents" / "Resources"
                      / "Claude Shield.app" / "Contents" / "MacOS" / "Shield")
        self.assertTrue(tower_exe.is_file())
        self.assertTrue(os.access(tower_exe, os.X_OK), "zipfile 解出来必须补回执行位")
        self.assertTrue(shield_exe.is_file(), "哨兵必须跟着塔一起进暂存目录")
        self.assertTrue(os.access(shield_exe, os.X_OK))
        state = updater.status("1.0.0", "1.0.0")
        self.assertTrue(state["stagedReady"])
        self.assertFalse(state["installing"])

    def test_tampered_zip_is_rejected(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        flipped = bytearray(self.tower_zip)
        flipped[len(flipped) // 2] ^= 0xFF
        self.release("/tower.zip", bytes(flipped))
        with self.assertRaises(updater.UpdateError) as ctx:
            updater.download(current_tower="1.0.0")
        self.assertIn("SHA256", str(ctx.exception))
        self.assertFalse(updater._staged_path("2.0.0").exists())

    def test_redirects_away_from_github_are_rejected(self):
        """只查第一跳等于没查：3xx 跳到白名单外也必须拦住。"""
        with self.assertRaises(updater.UpdateError) as ctx:
            updater._fetch(self.base + "/redirect-away", 1024)
        self.assertIn("不受信任", str(ctx.exception))
        dest = updater.STATE_DIR / "redirect.zip"
        with self.assertRaises(updater.UpdateError):
            updater._download_asset(
                {"url": self.base + "/redirect-away", "bytes": 1, "sha256": "0" * 64},
                dest)
        self.assertFalse(dest.exists())

    def test_manifest_size_mismatch_is_rejected(self):
        self.publish(manifest_extra={"assets": {
            "tower": {"name": "ClaudeTower.zip", "bytes": 1,
                      "sha256": hashlib.sha256(self.tower_zip).hexdigest()},
        }})
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="1.0.0")
        self.assertFalse(result["ok"])
        self.assertIn("体积", result["error"])

    def test_manifest_without_tower_is_rejected(self):
        self.publish(manifest_extra={"assets": {}})
        updater.configure("o/r")
        result = updater.check(force=True, current_tower="1.0.0")
        self.assertFalse(result["ok"])
        self.assertIn("tower", result["error"])

    def test_zip_traversal_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("Claude Tower.app/Contents/Info.plist", b"x")
            zf.writestr("../evil.sh", b"x")
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "bad.zip"
            src.write_bytes(buf.getvalue())
            with self.assertRaises(updater.UpdateError):
                updater._safe_extract(src, Path(tmp) / "out", "Claude Tower.app")

    def test_wrong_bundle_version_is_rejected(self):
        bad = tower_zip("9.9.9", "1.5.0")
        self.publish(tower=bad)
        self.release("/tower.zip", bad)
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        with self.assertRaises(updater.UpdateError) as ctx:
            updater.download(current_tower="1.0.0")
        self.assertIn("版本", str(ctx.exception))

    def test_nested_shield_version_must_match_manifest(self):
        """塔对、包里哨兵对不上：这是半截包，装上去就是「塔新哨兵旧」。"""
        bad = tower_zip("2.0.0", "1.4.0")
        self.publish(tower=bad)
        self.release("/tower.zip", bad)
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        with self.assertRaises(updater.UpdateError) as ctx:
            updater.download(current_tower="1.0.0")
        self.assertIn("Claude Shield.app", str(ctx.exception))
        self.assertFalse(updater._staged_path("2.0.0").exists())

    def test_bad_signature_is_rejected(self):
        CODESIGN["rc"] = 1
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        with self.assertRaises(updater.UpdateError) as ctx:
            updater.download(current_tower="1.0.0")
        self.assertIn("签名", str(ctx.exception))

    def test_download_without_check_is_refused(self):
        updater.configure("o/r")
        with self.assertRaises(updater.UpdateError):
            updater.download(current_tower="1.0.0")

    # ---- 安装 ----

    def test_install_requires_explicit_confirmation(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        updater.download(current_tower="1.0.0")
        with self.assertRaises(updater.UpdateError) as ctx:
            updater.install(confirm=False, current_tower="1.0.0")
        self.assertIn("确认", str(ctx.exception))

    def test_install_script_stops_python_child_and_rolls_back(self):
        run_dir = Path(tempfile.mkdtemp(prefix="ccclean-run-"))
        plan = {
            "log": str(run_dir / "update.log"), "result": str(run_dir / "result.json"),
            "active": str(run_dir / "active.json"), "stamp": str(run_dir / "stamp"),
            "tower_target": "/Applications/Claude Tower.app",
            "tower_new": "/tmp/new/tower/Claude Tower.app",
            "backup": str(run_dir / "backup"), "heartbeat": str(run_dir / "hb"),
            "runtime": str(run_dir / "runtime"), "stop_marker": str(run_dir / "stop"),
            "tower_version": "2.0.0", "shield_version": "1.5.0",
            "tower_from": "1.0.0", "shield_from": "1.0.0",
            "shield_was_running": "1", "launch": "1", "shield_pid": "123",
        }
        script = run_dir / "install.sh"
        updater._write_script(script, plan)
        text = script.read_text(encoding="utf-8")
        self.assertIn("Contents/Resources/python", text)
        self.assertIn('stop_under "$TOWER/Contents/Resources/python"', text)
        self.assertIn("move-old-tower", text)
        self.assertIn("rollback tower-not-starting", text)
        # 哨兵没有独立的安装目标：路径由塔算出来，换塔就等于换哨兵
        self.assertIn('SHIELD="$TOWER/Contents/Resources/Claude Shield.app"', text)
        self.assertNotIn("SHIELD_NEW", text)
        self.assertIn("missing-shield", text)
        self.assertIn("version-shield", text)
        # 过渡期可能有一个旧的独立哨兵在跑：按 pid 也停一次
        self.assertIn('/bin/kill -TERM "$SHIELD_PID"', text)
        self.assertIn("rollback shield-not-starting", text)
        # 塔会被脚本自己停掉，安装中标记必须由脚本接管，否则新塔启动后
        # 到结果落盘前会被当成「没在安装」，还能再点一次安装。
        self.assertIn('"pid":%s', text)
        self.assertIn('"$$"', text)
        self.assertIn("write_result 0", text)
        shutil.rmtree(run_dir, ignore_errors=True)

    def test_settings_are_locked_while_installing(self):
        updater.configure("o/r")
        updater._write_json(updater.RUN_DIR / "active.json",
                            {"pid": os.getpid(), "at": int(time.time()), "version": "2.0.0"})
        with self.assertRaises(updater.UpdateError):
            updater.configure("other/repo")
        with self.assertRaises(updater.UpdateError):
            updater.discard()
        updater.RUN_DIR.joinpath("active.json").unlink()

    # ---- 真跑安装脚本 ----

    def _stage_and_targets(self, new_tower_version="2.0.0"):
        root = Path(tempfile.mkdtemp(prefix="ccclean-e2e-"))
        staged = updater._staged_path("2.0.0")
        shutil.rmtree(staged, ignore_errors=True)
        real_tower(staged / "tower" / "Claude Tower.app", new_tower_version, "1.5.0")
        updater._save({"staged": {"version": "2.0.0", "shieldVersion": "1.5.0",
                                  "at": int(time.time()), "dir": "update-staging/2.0.0"}})
        target = real_tower(root / "Applications" / "Claude Tower.app", "1.0.0", "1.0.0")
        return root, target

    def _install_sync(self, target: Path):
        real_popen = subprocess.Popen

        def sync_popen(cmd, *args, **kwargs):
            proc = real_popen(cmd, *args, **kwargs)
            # 只等安装脚本；ps/codesign 的输出由调用方自己读管道，
            # 在这里先 wait 会和满管道互相等死。
            if cmd[:1] == ["/bin/sh"] and len(cmd) > 1 and cmd[1].endswith("install.sh"):
                proc.wait()
            return proc

        updater.subprocess.Popen = sync_popen
        try:
            return updater.install(confirm=True, current_tower="1.0.0",
                                   current_shield="1.0.0", tower_app=target,
                                   launch=False)
        finally:
            updater.subprocess.Popen = real_popen

    @staticmethod
    def _version(app: Path) -> str:
        plist = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
        return str(plist.get("CFBundleShortVersionString"))

    def test_real_script_swaps_tower_with_nested_shield(self):
        root, target = self._stage_and_targets()
        self._install_sync(target)
        self.assertEqual(self._version(target), "2.0.0")
        self.assertEqual(self._version(updater.nested_shield(target)), "1.5.0")
        backups = list(updater.BACKUP_DIR.iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(self._version(backups[0] / "Claude Tower.app.new"), "1.0.0")
        state = updater.status("2.0.0", "1.5.0")
        self.assertTrue(state["lastInstall"]["ok"])
        self.assertIsNone(state["staged"])
        leftovers = [p.name for p in target.parent.iterdir() if ".ccclean-" in p.name]
        self.assertEqual(leftovers, [])
        shutil.rmtree(root, ignore_errors=True)

    def test_real_script_rolls_back_on_wrong_version(self):
        root, target = self._stage_and_targets(new_tower_version="9.9.9")
        self._install_sync(target)
        self.assertEqual(self._version(target), "1.0.0")
        self.assertEqual(self._version(updater.nested_shield(target)), "1.0.0")
        state = updater.status("1.0.0", "1.0.0")
        self.assertFalse(state["lastInstall"]["ok"])
        self.assertIn("版本号", state["lastInstall"]["reasonText"])
        leftovers = [p.name for p in target.parent.iterdir() if ".ccclean-" in p.name]
        self.assertEqual(leftovers, [])
        shutil.rmtree(root, ignore_errors=True)

    def test_install_plan_uses_backup_and_running_bundle(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        updater.download(current_tower="1.0.0")
        tower_app = Path(tempfile.mkdtemp(prefix="ccclean-tower-")) / "Claude Tower.app"
        tower_app.mkdir()
        spawned = {}
        real_popen = subprocess.Popen

        class FakeProc:
            pid = 4242

        def fake_popen(cmd, *args, **kwargs):
            # 只拦安装脚本本身；`sh -n` 和 ps 这些还得真跑
            if cmd[:1] == ["/bin/sh"] and len(cmd) > 1 and cmd[1].endswith("install.sh"):
                spawned["cmd"] = cmd
                return FakeProc()
            return real_popen(cmd, *args, **kwargs)

        saved_popen = updater.subprocess.Popen
        updater.subprocess.Popen = fake_popen
        try:
            result = updater.install(confirm=True, current_tower="1.0.0",
                                     current_shield="1.0.0", tower_app=tower_app,
                                     launch=False)
        finally:
            updater.subprocess.Popen = saved_popen
        self.assertTrue(result["started"])
        self.assertEqual(spawned["cmd"][0], "/bin/sh")
        script = Path(spawned["cmd"][1])
        text = script.read_text(encoding="utf-8")
        self.assertIn(str(tower_app), text)
        self.assertIn("update-backup", text)
        self.assertNotIn("shield_new", text)
        self.assertEqual(updater.status("1.0.0", "1.0.0")["installing"], True)
        # 收尾：假装脚本已经写完结果，避免后续用例看到「安装中」
        updater._write_json(updater.RUN_DIR / "result.json",
                            {"ok": True, "at": int(time.time()), "to": "2.0.0",
                             "from": "1.0.0", "reason": ""})
        shutil.rmtree(tower_app.parent, ignore_errors=True)

    # ---- 结果收编 ----

    def test_successful_result_clears_staging_and_prunes_backups(self):
        updater.configure("o/r")
        updater.check(force=True, current_tower="1.0.0")
        updater.download(current_tower="1.0.0")
        for name in ("20260101-000000-1.0.0", "20260102-000000-1.0.0",
                     "20260103-000000-1.0.0"):
            (updater.BACKUP_DIR / name).mkdir(parents=True, exist_ok=True)
        updater._write_json(updater.RUN_DIR / "result.json",
                            {"ok": True, "at": int(time.time()), "to": "2.0.0",
                             "from": "1.0.0", "reason": ""})
        state = updater.status("2.0.0", "1.5.0")
        self.assertEqual(state["lastInstall"]["to"], "2.0.0")
        self.assertIsNone(state["staged"])
        self.assertFalse(updater._staged_path("2.0.0").exists())
        left = sorted(p.name for p in updater.BACKUP_DIR.iterdir())
        self.assertEqual(left, ["20260102-000000-1.0.0", "20260103-000000-1.0.0"])

    def test_rolled_back_result_explains_why(self):
        updater.configure("o/r")
        updater._write_json(updater.RUN_DIR / "result.json",
                            {"ok": False, "at": int(time.time()), "to": "2.0.0",
                             "from": "1.0.0", "reason": "tower-not-starting"})
        state = updater.status("1.0.0", "1.0.0")
        self.assertFalse(state["lastInstall"]["ok"])
        self.assertIn("没有响应", state["lastInstall"]["reasonText"])

    def test_shield_request_marker_is_consumed_once(self):
        updater.configure("o/r")
        updater._write_json(updater.REQUEST_FILE, {"at": int(time.time())})
        self.assertTrue(updater.status("1.0.0", "1.0.0")["requested"])
        self.assertFalse(updater.status("1.0.0", "1.0.0")["requested"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
