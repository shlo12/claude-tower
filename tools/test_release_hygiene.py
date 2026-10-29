import hashlib
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from check_release import history_issues, issues, load_private_name_hashes


class ReleaseHygieneTests(unittest.TestCase):
    def test_blocks_private_path_and_agent_files(self):
        self.assertTrue(issues('app.py', b'/Users/' + b'example-user/private'))
        self.assertTrue(issues('.workbuddy-ai/memory/a.md', b'private'))

    def test_blocks_attribution_and_credentials(self):
        with patch('check_release.DENIED_TOKEN_HASHES', {hashlib.sha256(b'example-upstream').hexdigest()}):
            self.assertTrue(issues('README.md', b'https://example.test/Example-Upstream'))
        self.assertTrue(issues('a.py', b'sk-ant-' + b'A' * 40))

    def test_private_profile_is_optional_and_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            profile = Path(folder) / 'markers.json'
            with patch('check_release.PRIVATE_PROFILE', profile):
                self.assertEqual(load_private_name_hashes(), set())
                digest = hashlib.sha256(b'fixture').hexdigest()
                profile.write_text(json.dumps({'private_name_hashes': [digest]}))
                self.assertEqual(load_private_name_hashes(), {digest})
                profile.write_text('{invalid')
                with self.assertRaisesRegex(RuntimeError, '停止检查'):
                    load_private_name_hashes()
                profile.write_text(json.dumps({'private_name_hashes': ['invalid']}))
                with self.assertRaisesRegex(RuntimeError, '停止检查'):
                    load_private_name_hashes()

    def test_private_names_are_detected_without_embedding_real_names(self):
        example = '甲乙丙'
        digest = hashlib.sha256(example.encode()).hexdigest()
        with patch('check_release.PRIVATE_NAME_HASHES', {digest}):
            self.assertIn('personal name', issues('a.py', ('前缀' + example + '后缀').encode()))

    def test_license_files_do_not_bypass_privacy_checks(self):
        self.assertTrue(issues('LICENSE.txt', b'/Users/' + b'example-user/private'))
        self.assertTrue(issues('LICENSE.txt', b'sk-ant-' + b'A' * 40))

    def test_agent_markers_ignore_case(self):
        self.assertTrue(issues('a.py', b'Generated ' + b'by Codex'))
        self.assertTrue(issues('a.py', b'Co-Authored-By' + b': test'))

    def test_history_checks_old_blobs_and_messages(self):
        payload = b'/Users/' + b'example-user/old-file'
        raw = b'abc blob ' + str(len(payload)).encode() + b'\n' + payload + b'\n'
        with patch('check_release.subprocess.check_output', side_effect=[
                'abc removed.py\n', b'Generated ' + b'by Codex']), patch(
                'check_release.subprocess.run', return_value=SimpleNamespace(stdout=raw)):
            found = history_issues()
        self.assertTrue(any('history abc/removed.py' in f for f in found))
        self.assertTrue(any('commit messages' in f for f in found))

    def test_keeps_dependency_notices_and_detection_names(self):
        self.assertFalse(issues('runtime/LICENSE.txt', b'Copyright Guido van Rossum'))
        self.assertFalse(issues('scanner.py', b'Cursor Codex DeepSeek'))
        self.assertFalse(issues('AUTHORS.md', b'shlo'))


if __name__ == '__main__':
    unittest.main()
