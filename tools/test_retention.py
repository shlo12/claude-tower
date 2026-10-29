#!/usr/bin/env python3
"""临时 HOME 中验证不可逆清理、所有副本入口及脱敏记录；不使用真实凭据。"""
import json
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import cleaner, compat, isolation, retention, scanner


class RetentionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ccclean-retention-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.cfg = self.home / ".claude"
        self.cfg.mkdir()
        self.backups = self.home / ".ccclean/backups"
        for module, values in [
            (cleaner, dict(HOME=self.home, BACKUP_DIR=self.backups, TRASH_DIR=self.home / ".Trash")),
            (scanner, dict(HOME=self.home, CLAUDE_DIR=self.cfg, CLAUDE_JSON=self.home / ".claude.json",
                           SHELL_RC=[self.home / ".zshrc", self.home / ".zprofile"], KEYCHAIN_SERVICES=[])),
            (compat, dict(HOME=self.home, IS_MAC=True, IS_WIN=False)),
            (isolation, dict(HOME=self.home, PROFILE_DIR=self.home / ".ccclean/profiles")),
        ]:
            p = patch.multiple(module, **values)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(compat, "ancestor_names", return_value=[])
        p.start()
        self.addCleanup(p.stop)

    def write(self, rel, data):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data if isinstance(data, str) else json.dumps(data))
        return p

    def item(self, kind, path=None, **values):
        return {"id": "test.operation", "title": "测试操作", "severity": "high",
                "fix": {"kind": kind, **({"path": str(path)} if kind == "trash" else
                         {"file": str(path)} if path else {}), **values}}

    def execute(self, item):
        result = cleaner.execute([item], [item["id"]], "CLEAN")
        self.assertTrue(result["ok"], result)
        return result

    def entries(self, result):
        p = self.home / result["backupDir"][2:] / "manifest.json"
        return json.loads(p.read_text())["entries"]

    def assert_no_copies(self, secret):
        for root in (self.backups, self.home / ".Trash"):
            if root.exists():
                for path in root.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(secret.encode(), path.read_bytes(), str(path))

    def test_cache_and_log_deletions_never_use_trash(self):
        for name in ("debug", "telemetry", "statsig", "logs", "shell-snapshots", "session-env"):
            with self.subTest(name=name):
                p = self.write(f".claude/{name}/old.txt", "DUMMY-PRIVATE-LOG").parent
                item = self.item("trash", p)
                plan = cleaner.build_plan([item], [item["id"]])
                self.assertEqual(plan["ops"][0]["kind"], "purge")
                self.assertIn("无法还原", plan["ops"][0]["risk"])
                result = self.execute(item)
                self.assertFalse(p.exists())
                self.assertIsNone(result["trashDir"])
                self.assertEqual(self.entries(result), [{"kind": "no_copy", "action": "cache", "ok": True}])
        self.assert_no_copies("DUMMY-PRIVATE-LOG")

    def test_clean_confirmation_still_required_for_purge(self):
        p = self.write(".claude/debug/log.txt", "DUMMY")
        item = self.item("trash", p.parent)
        with self.assertRaises(cleaner.CleanError):
            cleaner.execute([item], [item["id"]], "")
        self.assertTrue(p.exists())

    def test_credentials_and_desktop_tokens_not_retained(self):
        for rel in (".claude/.credentials.json", ".claude/credentials.json",
                    "Library/Application Support/Claude/storage.json"):
            p = self.write(rel, {"accessToken": "DUMMY-OAUTH"})
            target = p.parent if "Application Support" in rel else p
            result = self.execute(self.item("trash", target))
            self.assertFalse(target.exists())
            self.assertEqual(self.entries(result)[0]["action"], "credential")
        self.assert_no_copies("DUMMY-OAUTH")

    def test_key_removal_keeps_other_preferences_but_not_original(self):
        p = self.write(".claude/settings.json", {"model": "keep", "env": {"ANTHROPIC_API_KEY": "DUMMY-API-KEY"}})
        item = self.item("json_keys", p, keys=["env.ANTHROPIC_API_KEY"])
        result = self.execute(item)
        self.assertEqual(json.loads(p.read_text()), {"model": "keep"})
        self.assert_no_copies("DUMMY-API-KEY")
        self.assertEqual(set(self.entries(result)[0]), {"kind", "action", "ok"})
        self.assertEqual(cleaner.list_backups()[0]["restorable"], 0)

    def test_other_configuration_edit_does_not_copy_keys(self):
        p = self.write(".claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "DUMMY-UNCHANGED"}})
        self.execute(self.item("json_patch", p, set={"permissions.defaultMode": "default"}))
        self.assertEqual(json.loads(p.read_text())["env"]["ANTHROPIC_API_KEY"], "DUMMY-UNCHANGED")
        self.assert_no_copies("DUMMY-UNCHANGED")

    def test_plain_preferences_are_backed_up_and_restorable(self):
        p = self.write(".claude/settings.json", {"model": "keep", "hooks": {"Test": []}})
        result = self.execute(self.item("json_keys", p, keys=["hooks"]))
        bid = Path(result["backupDir"]).name
        self.assertTrue(cleaner.restore(bid, "RESTORE")["ok"])
        self.assertIn("hooks", json.loads(p.read_text()))

    def test_shell_keys_multiple_files_old_comments_and_multiline(self):
        a = self.write(".zshrc", '# [ccclean] export ANTHROPIC_API_KEY="DUMMY-COMMENTED"\nexport KEEP=one\n')
        b = self.write(".zprofile", 'export ANTHROPIC_AUTH_TOKEN="DUMMY-MULTILINE\nsecond-part"\nexport KEEP=two\n')
        items = [it for it in scanner.check_credential() if it["id"].startswith("cred.shell_keys.")]
        self.assertEqual(len(items), 2)
        self.assertNotIn("DUMMY", json.dumps(items))
        result = cleaner.execute(items, [it["id"] for it in items], "CLEAN")
        self.assertTrue(result["ok"], result)
        self.assertEqual(a.read_text(), "export KEEP=one\n")
        self.assertEqual(b.read_text(), "export KEEP=two\n")
        self.assert_no_copies("DUMMY")
        self.assertTrue(all(e["kind"] == "no_copy" for e in self.entries(result)))

    def test_shell_backslash_continuation_removed_together(self):
        p = self.write(".zshrc", 'export ANTHROPIC_API_KEY=\\\nDUMMY-CONTINUED\nexport KEEP=yes\n')
        self.execute(self.item("shellrc", p, lines=[1]))
        self.assertEqual(p.read_text(), "export KEEP=yes\n")
        self.assert_no_copies("DUMMY-CONTINUED")

    def test_mixed_shell_commands_fail_without_copy_or_modification(self):
        raw = 'export ANTHROPIC_API_KEY=DUMMY-MIXED; export KEEP=yes\n'
        p = self.write(".zshrc", raw)
        item = self.item("shellrc", p, lines=[1])
        result = cleaner.execute([item], [item["id"]], "CLEAN")
        self.assertFalse(result["ok"])
        self.assertEqual(p.read_text(), raw)
        self.assert_no_copies("DUMMY-MIXED")
        self.assertFalse(self.entries(result)[0]["ok"])

    def test_unselected_key_does_not_get_copied_with_proxy_change(self):
        p = self.write(".zshrc", "export OPENAI_API_KEY=DUMMY-OTHER\nexport HTTPS_PROXY=http://localhost:1234\n")
        self.execute(self.item("shellrc", p, lines=[2]))
        self.assertTrue(p.read_text().startswith("export OPENAI_API_KEY=DUMMY-OTHER\n# [ccclean]"))
        self.assert_no_copies("DUMMY-OTHER")

    def test_snapshot_filters_all_copy_paths_and_preserves_sources(self):
        sensitive = [".claude/.credentials.json", ".claude/backups/.claude.json.backup.test",
                     ".claude/plugins/auth.json", ".claude.json"]
        for rel in sensitive:
            self.write(rel, {"nested": {"refreshToken": "DUMMY-SNAPSHOT"}})
        self.write(".claude/debug/trace.txt", "DUMMY-LOG")
        self.write(".claude/telemetry/queued.json", "DUMMY-EVENT")
        self.write(".claude/settings.json", {"model": "keep"})
        self.write(".claude/skills/test/SKILL.md", "user asset")
        (self.cfg / "outside-link").symlink_to(self.home / ".claude.json")
        result = cleaner.full_snapshot()
        dest = self.home / result["path"][2:]
        self.assertTrue((dest / "dot-claude/settings.json").exists())
        self.assertTrue((dest / "dot-claude/skills/test/SKILL.md").exists())
        self.assertFalse((dest / "dot-claude/debug").exists())
        self.assertFalse((dest / "dot-claude/outside-link").exists())
        self.assertFalse((dest / "claude.json").exists())
        self.assertGreater(result["excludedEntries"], 0)
        self.assert_no_copies("DUMMY")
        for rel in sensitive:
            self.assertTrue((self.home / rel).exists())

    def make_legacy(self, data, kind="json_keys", path=None):
        target = path or self.cfg / "settings.json"
        batch = self.backups / "20261024-120000"
        stored = batch / "files" / target.relative_to(self.home)
        stored.parent.mkdir(parents=True, exist_ok=True)
        stored.write_text(json.dumps(data))
        (batch / "manifest.json").write_text(json.dumps({"entries": [
            {"kind": kind, "path": str(target), "id": "legacy"}]}))
        return batch.name

    def test_legacy_secret_backup_cannot_be_reintroduced(self):
        current = self.write(".claude/settings.json", {"model": "current"})
        bid = self.make_legacy({"env": {"ANTHROPIC_AUTH_TOKEN": "DUMMY-OLD"}})
        result = cleaner.restore(bid, "RESTORE")
        self.assertFalse(result["ok"])
        self.assertEqual(json.loads(current.read_text()), {"model": "current"})
        self.assertFalse((self.backups / bid / "pre-restore").exists())

    def test_restore_does_not_snapshot_or_overwrite_current_key(self):
        current = self.write(".claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "DUMMY-NEW"}})
        bid = self.make_legacy({"model": "old"})
        result = cleaner.restore(bid, "RESTORE")
        self.assertFalse(result["ok"])
        self.assertIn("DUMMY-NEW", current.read_text())
        self.assert_no_copies("DUMMY-NEW")

    def test_profile_delete_never_moves_credentials_to_trash(self):
        p = self.write(".ccclean/profiles/test/claude/.credentials.json", {"accessToken": "DUMMY-PROFILE"})
        self.assertTrue(isolation.delete_profile("test")["ok"])
        self.assertFalse(p.parent.parent.exists())
        self.assertFalse((self.home / ".Trash").exists())

    def test_first_backup_is_not_overwritten_by_another_operation(self):
        p = self.write(".claude.json", {"projects": {"test": {}}, "userID": "old-id"})
        batch = self.backups / "test"
        cleaner._apply_json_keys({"path": str(p), "keys": ["projects"]}, batch)
        cleaner._apply_rotate_ids({"path": str(p), "rotate": ["userID"], "keys": []}, batch)
        self.assertIn("projects", json.loads((batch / "files/.claude.json").read_text()))

    def test_fish_and_powershell_assignments_are_recognized(self):
        for line in ("set -gx ANTHROPIC_API_KEY DUMMY\n", "$env:ANTHROPIC_API_KEY = 'DUMMY'\n"):
            self.assertEqual(retention.shell_secret_spans(line, strict=True), [(1, 1)])

    def test_directory_cleanup_filters_embedded_credentials_before_trash(self):
        safe = self.write(".claude/projects/test/notes.txt", "keep this user asset")
        self.write(".claude/projects/test/auth.json", {"token": "DUMMY-EMBEDDED"})
        self.write(".claude/projects/test/trace.log", "DUMMY-LOG")
        item = self.item("trash", safe.parent)
        result = self.execute(item)
        self.assertEqual(self.entries(result)[0]["detail"]["privateRemoved"], 2)
        self.assert_no_copies("DUMMY")
        self.assertIn("keep this user asset", (self.home / result["trashDir"][2:] / "test/notes.txt").read_text())

    def test_write_failure_cleans_temporary_file_without_copying_credentials(self):
        p = self.write(".claude/settings.json", {"env": {"ANTHROPIC_API_KEY": "DUMMY-WRITE"}})
        item = self.item("json_keys", p, keys=["env.ANTHROPIC_API_KEY"])
        with patch.object(cleaner.os, "replace", side_effect=OSError("write failed")):
            result = cleaner.execute([item], [item["id"]], "CLEAN")
        self.assertFalse(result["ok"])
        self.assertIn("DUMMY-WRITE", p.read_text())
        self.assertEqual(list(self.cfg.glob(".ccclean-write-*")), [])
        self.assert_no_copies("DUMMY-WRITE")

    def test_same_read_is_checked_and_written_despite_source_change(self):
        p = self.write(".claude/settings.json", {"model": "safe-before-change"})
        original = retention.copy_allowed
        def changed(path, home, data=None):
            path.write_text('{"token":"DUMMY-RACE"}')
            return original(path, home, data)
        with patch.object(retention, "copy_allowed", side_effect=changed):
            target = cleaner._backup_file(p, self.backups / "race")
        self.assertTrue(target)
        self.assertIn("safe-before-change", target.read_text())
        self.assert_no_copies("DUMMY-RACE")

    def test_credential_services_and_env_audit_have_no_original_values(self):
        item = self.item("keychain", service="private-service-name")
        with patch.object(compat, "delete_keychain", return_value=(True, "")):
            result = self.execute(item)
        self.assertEqual(self.entries(result), [{"kind": "no_copy", "action": "credential", "ok": True}])

    def test_launchagent_with_secret_is_deleted_without_trash(self):
        p = self.write(".claude/launch.plist", '<?xml version="1.0"?><plist version="1.0"><dict>'
                       '<key>EnvironmentVariables</key><dict><key>ANTHROPIC_API_KEY</key>'
                       '<string>DUMMY-LAUNCH</string></dict></dict></plist>')
        item = self.item("startup", items=[{"name": "test", "path": str(p), "kind": "launchagent"}])
        with patch.object(compat, "run", return_value=""):
            self.execute(item)
        self.assertFalse(p.exists())
        self.assert_no_copies("DUMMY-LAUNCH")

    def test_resolved_home_still_matches_cache_policy(self):
        alias = self.home / "home-alias"
        alias.symlink_to(self.home, target_is_directory=True)
        self.assertEqual(retention.path_category(self.cfg / "debug", alias), "cache")

    def test_binary_user_assets_are_not_misclassified_as_credentials(self):
        p = self.home / ".claude/projects/test/asset.png"
        p.parent.mkdir(parents=True)
        data = b'\x89PNG\x00\xff\x80image-data'
        p.write_bytes(data)
        result = self.execute(self.item("trash", p.parent))
        retained = self.home / result["trashDir"][2:] / "test/asset.png"
        self.assertEqual(retained.read_bytes(), data)
        self.assertTrue(cleaner.restore(Path(result["backupDir"]).name, "RESTORE")["ok"])
        self.assertEqual(p.read_bytes(), data)

    def test_binary_plist_credentials_are_still_detected(self):
        data = plistlib.dumps({"EnvironmentVariables": {"ANTHROPIC_API_KEY": "DUMMY-BINARY"}}, fmt=plistlib.FMT_BINARY)
        self.assertTrue(retention.contains_secret(data))


if __name__ == "__main__":
    unittest.main()
