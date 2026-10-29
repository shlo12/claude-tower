"""持久隐私设置回归：仅操作临时目录，绝不提权或修改真实 hosts。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core import privacy
import app


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.cfg = self.root / 'claude/settings.json'
        self.state = self.root / 'state/privacy.json'
        self.hosts = self.root / 'hosts'
        self.original_hosts = '127.0.0.1 localhost\n# other tool\n10.0.0.1 internal.example\n'
        self.hosts.write_text(self.original_hosts)
        for target, val in [('CONFIG', self.cfg), ('STATE', self.state), ('HOSTS', self.hosts)]:
            p = patch.object(privacy, target, val)
            p.start(); self.addCleanup(p.stop)
        p = patch.object(privacy.compat, 'IS_MAC', True)
        p.start(); self.addCleanup(p.stop)
        p = patch.object(privacy, '_authorize_hosts', side_effect=self.authorize)
        self.auth = p.start(); self.addCleanup(p.stop)

    def authorize(self, enable):
        result = subprocess.run(['/usr/bin/awk', privacy.STRIP_AWK], input=self.hosts.read_text(),
                                text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError('malformed markers')
        self.hosts.write_text(result.stdout + (privacy.block() if enable else ''))

    def write_cfg(self, data):
        self.cfg.parent.mkdir(exist_ok=True)
        self.cfg.write_text(json.dumps(data))

    def test_enable_repeat_and_restore_original(self):
        original = {'model': 'keep', 'env': {'CUSTOM': 'keep', 'DISABLE_TELEMETRY': ''}}
        self.write_cfg(original)
        self.assertTrue(privacy.apply(True)['hostsConfigured'])
        snapshot = self.state.read_text()
        privacy.apply(True)
        self.assertEqual(self.state.read_text(), snapshot)
        self.assertEqual(self.hosts.read_text().count(privacy.BEGIN), 1)
        privacy.apply(False)
        self.assertEqual(json.loads(self.cfg.read_text()), original)
        self.assertEqual(self.hosts.read_text(), self.original_hosts)
        self.assertFalse(self.state.exists())

    def test_new_config_is_removed_on_restore(self):
        privacy.apply(True)
        self.assertEqual(self.cfg.stat().st_mode & 0o777, 0o600)
        privacy.apply(False)
        self.assertFalse(self.cfg.exists())

    def test_preserve_later_edits_and_hosts(self):
        privacy.apply(True)
        data = json.loads(self.cfg.read_text())
        data['env']['DISABLE_TELEMETRY'] = 'later-value'
        data['model'] = 'later-model'
        self.write_cfg(data)
        self.hosts.write_text(self.hosts.read_text() + '10.1.1.1 later.example\n')
        privacy.apply(False)
        self.assertEqual(json.loads(self.cfg.read_text()), {'env': {'DISABLE_TELEMETRY': 'later-value'}, 'model': 'later-model'})
        self.assertIn('later.example', self.hosts.read_text())

    def test_cancel_authorization_does_not_change_targets(self):
        self.auth.side_effect = RuntimeError('cancelled')
        with self.assertRaises(RuntimeError): privacy.apply(True)
        self.assertFalse(self.cfg.exists())
        self.assertEqual(self.hosts.read_text(), self.original_hosts)
        self.assertTrue(privacy.status()['restoreAvailable'])

    def test_invalid_json_rejected_before_authorization(self):
        self.cfg.parent.mkdir()
        self.cfg.write_text('{bad')
        with self.assertRaises(ValueError): privacy.apply(True)
        self.auth.assert_not_called()

    def test_symlink_rejected(self):
        self.cfg.parent.mkdir()
        self.cfg.symlink_to(self.hosts)
        with self.assertRaises(ValueError): privacy.apply(True)
        self.auth.assert_not_called()

    def test_concurrent_config_edit_is_not_overwritten(self):
        def auth(enable):
            self.authorize(enable)
            self.write_cfg({'model': 'concurrent'})
        self.auth.side_effect = auth
        with self.assertRaisesRegex(RuntimeError, '同时'): privacy.apply(True)
        self.assertEqual(json.loads(self.cfg.read_text()), {'model': 'concurrent'})
        self.assertTrue(privacy.status()['restoreAvailable'])

    def test_corrupt_restore_record_rejected(self):
        self.state.parent.mkdir()
        self.state.write_text('[]')
        with self.assertRaises(ValueError): privacy.apply(True)
        self.auth.assert_not_called()

    def test_malformed_host_markers_not_rewritten(self):
        for raw in [privacy.BEGIN + '\n', privacy.END + '\n', privacy.block() * 2]:
            self.hosts.write_text(raw)
            with self.assertRaises(RuntimeError): privacy.apply(True)
            self.assertEqual(self.hosts.read_text(), raw)
            self.assertFalse(self.cfg.exists())

    def test_root_scripts_parse_without_execution(self):
        for enable in (True, False):
            script = privacy._hosts_script(enable)
            result = subprocess.run(['/bin/sh', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('0.0.0.0 api.anthropic.com', script)
            self.assertNotIn('launchctl', script)


class ApiTests(unittest.TestCase):
    def handler(self, host='127.0.0.1:8787', token=None, origin=None, confirmed=True):
        h = object.__new__(app.Handler)
        h.path = '/api/privacy'
        h.server = SimpleNamespace(server_port=8787)
        h.headers = {'Host': host, 'X-CClean-Privacy-Token': token or app.PRIVACY_TOKEN}
        if origin: h.headers['Origin'] = origin
        h._body = lambda: {'action': 'enable', 'confirm': confirmed}
        h._err, h._json = Mock(), Mock()
        return h

    def test_cross_origin_rebinding_and_missing_confirmation_rejected(self):
        for h in [self.handler(host='evil.example:8787'), self.handler(token='wrong'),
                  self.handler(origin='https://evil.example'), self.handler(confirmed=False)]:
            with patch.object(app.privacy, 'apply') as apply:
                h.do_POST()
                apply.assert_not_called()
                h._err.assert_called_once()

    def test_local_confirmed_request(self):
        h = self.handler()
        with patch.object(app.privacy, 'apply', return_value={}) as apply:
            h.do_POST()
            apply.assert_called_once_with(True)
            h._json.assert_called_once()


if __name__ == '__main__': unittest.main()
