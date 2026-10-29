"""离线回归：遥测配置、预览/备份写入与观察哨，不读取用户配置。"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import cleaner, deep, telemetry, watch


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = self.root / ".claude"
        self.cfg.mkdir()
        self.path = self.cfg / "settings.json"

    def inspect(self, settings=None, env=None):
        if settings is not None:
            self.path.write_text(json.dumps(settings))
        return {x["id"].split(".")[-1]: x for x in telemetry.inspect(self.cfg, env or {})}

    def test_empty_and_false_semantics(self):
        for value, closed in [("", False), ("0", True), ("false", True), ("1", True)]:
            with self.subTest(value=value):
                r = self.inspect({"env": {"DISABLE_TELEMETRY": value}})
                self.assertEqual(r["metrics"]["configuredOff"], closed)

    def test_error_and_feedback_are_independent(self):
        for key, channel in [("DISABLE_ERROR_REPORTING", "errors"), ("DISABLE_FEEDBACK_COMMAND", "feedback")]:
            r = self.inspect({"env": {key: "1"}})
            self.assertTrue(r[channel]["configuredOff"])
            self.assertFalse(r["metrics"]["configuredOff"])

    def test_feedback_and_do_not_track_boolean(self):
        r = self.inspect({"env": {"DISABLE_FEEDBACK_COMMAND": "0", "DO_NOT_TRACK": "0"}})
        self.assertFalse(r["feedback"]["configuredOff"])
        self.assertFalse(r["metrics"]["configuredOff"])

    def test_global_off_does_not_hide_otel(self):
        r = self.inspect({"env": {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                                 "CLAUDE_CODE_ENABLE_TELEMETRY": "1"}})
        self.assertTrue(all(r[c]["configuredOff"] for c in ("metrics", "errors", "feedback")))
        self.assertIn("检测到启用", r["otel"]["title"])

    def test_config_directory_and_environment_source(self):
        self.path.write_text('{"env":{"DISABLE_TELEMETRY":"1"}}')
        r = telemetry.inspect(environ={"CLAUDE_CONFIG_DIR": str(self.cfg), "DISABLE_TELEMETRY": ""})
        self.assertFalse(r[0]["configuredOff"])
        self.assertIn("待核实", r[0]["evidence"][0]["value"])

    def test_invalid_config_has_no_fix(self):
        for raw in ['{bad', '[]', '{"env":[]}']:
            self.path.write_text(raw)
            r = self.inspect()
            self.assertIsNone(r["metrics"]["fix"])
            self.assertIn("待核实", r["metrics"]["title"])
            self.assertEqual(self.path.read_text(), raw)

    def test_preview_and_apply_preserve_preferences_and_backup(self):
        original = {"model": "keep-me", "env": {"CUSTOM": "keep-me"}}
        self.path.write_text(json.dumps(original))
        self._apply_and_check(original)

    def test_create_missing_settings(self):
        self._apply_and_check(None)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def _apply_and_check(self, original):
        items = telemetry.inspect(self.cfg, {})[:len(telemetry.CHANNELS)]
        before = json.dumps(items)
        with patch.object(cleaner, "HOME", self.root):
            plan = cleaner.build_plan(items, [x["id"] for x in items])
            self.assertEqual(len(plan["ops"]), 1)
            self.assertEqual(json.dumps(items), before)
            self.assertEqual(self.path.exists(), original is not None)
            backup = self.root / "backup"
            result = cleaner._apply_json_patch(plan["ops"][0], backup)
        self.assertTrue(result["ok"])
        data = json.loads(self.path.read_text())
        for _, _, key in telemetry.CHANNELS:
            self.assertEqual(data["env"][key], "1")
        if original:
            self.assertEqual(data["model"], original["model"])
            self.assertEqual(data["env"]["CUSTOM"], "keep-me")
            self.assertEqual(json.loads((backup / "files/.claude/settings.json").read_text()), original)
        self.assertTrue(all(x["configuredOff"] for x in telemetry.inspect(self.cfg, {})[:len(telemetry.CHANNELS)]))

    def test_target_classification_and_rules(self):
        self.assertIn("Datadog", telemetry.target_label(telemetry.DATADOG_HOSTS[0]))
        self.assertIn("Sentry", telemetry.target_label("o123.ingest.us.sentry.io"))
        self.assertEqual(telemetry.target_label("sentry.io.example.com"), "未分类")
        rules = deep.telemetry_block_text()
        for host in telemetry.DATADOG_HOSTS:
            self.assertIn("0.0.0.0 " + host, rules)
        self.assertNotIn("0.0.0.0 api.anthropic.com", rules)

    def test_observer_start_stop_logs_without_nested_lock_deadlock(self):
        with patch.object(watch, "_Server") as server, patch.object(watch.threading, "Thread"), \
                patch.object(watch, "LOG_FILE", self.root / "watch.log"), patch.object(watch, "STATE_DIR", self.root):
            server.return_value.server_address = ("127.0.0.1", 12345)
            try:
                self.assertTrue(watch.start()["running"])
                self.assertTrue(watch.status()["log"])
            finally:
                watch.stop()
            server.return_value.shutdown.assert_called_once()


if __name__ == "__main__":
    unittest.main()
