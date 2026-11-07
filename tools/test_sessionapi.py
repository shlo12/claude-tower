#!/usr/bin/env python3
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from core import sessionapi as s

class SessionApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.cfg={'patchClashConfig':{'external-controller':'','secret':'','dns':{'nameserver':['example']}},'other':'keep'}
        self.original=copy.deepcopy(self.cfg)
        def write(cfg):self.cfg=copy.deepcopy(cfg);return True
        for p in (patch.object(s,'STATE',Path(self.tmp.name)/'state.json'),
                  patch.object(s.compat,'IS_MAC',True),
                  patch.object(s.compat,'claude_processes',return_value=[]),
                  patch.object(s.proxyfix,'_flclash_settings',side_effect=lambda:(copy.deepcopy(self.cfg),'')),
                  patch.object(s.proxyfix,'_write_settings',side_effect=write),
                  patch.object(s.proxyfix,'_proc_alive',return_value=True),
                  patch.object(s.proxyfix,'_quit',return_value=True),
                  patch.object(s.proxyfix,'_launch',return_value=True),
                  patch.object(s.history,'LOG',Path(self.tmp.name)/'history.jsonl')):
            p.start();self.addCleanup(p.stop)
    def test_local_only_secret_and_exact_restore(self):
        s.apply('apply')
        cfg=self.cfg['patchClashConfig']
        self.assertTrue(cfg['external-controller'].startswith('127.0.0.1:'))
        self.assertGreaterEqual(len(cfg['secret']),32)
        self.assertNotIn(cfg['secret'],s.STATE.read_text())
        self.assertEqual(s.STATE.stat().st_mode&0o777,0o600)
        s.apply('undo')
        self.assertEqual(self.cfg,self.original)
        self.assertFalse(s.STATE.exists())
    def test_existing_api_is_not_overwritten(self):
        self.cfg['patchClashConfig']['external-controller']='127.0.0.1:9000'
        before=copy.deepcopy(self.cfg)
        with self.assertRaises(ValueError):s.apply('apply')
        self.assertEqual(self.cfg,before)
    def test_user_changed_secret_still_removes_our_endpoint(self):
        s.apply('apply')
        endpoint=self.cfg['patchClashConfig']['external-controller']
        self.cfg['patchClashConfig']['secret']='changed-by-user'
        s.apply('undo')
        # 我们加的接口要撤掉，但用户后来设的密钥不能替他删。
        self.assertNotEqual(self.cfg['patchClashConfig'].get('external-controller'),endpoint)
        self.assertEqual(self.cfg['patchClashConfig'].get('secret'),'changed-by-user')
        self.assertFalse(s.STATE.exists())
    def test_missing_endpoint_discards_record_without_touching_client(self):
        # 用户在客户端界面里把接口改回去了，或者上次写到一半就崩了。
        # 这时候没有可恢复的东西：要能收场，不能永久卡在「可恢复」。
        s.apply('apply')
        self.cfg['patchClashConfig'].pop('external-controller')
        before=copy.deepcopy(self.cfg)
        res=s.apply('undo')
        self.assertTrue(res['ok'])
        self.assertEqual(self.cfg,before)
        self.assertFalse(s.STATE.exists())
        # 收场之后必须还能重新启用，否则用户就真的没法再用了。
        s.apply('apply')
        self.assertTrue(s.STATE.exists())
    def test_state_failure_does_not_write_new_interface(self):
        with patch.object(s,'_save',side_effect=OSError('full')):
            with self.assertRaises(OSError):s.apply('apply')
        self.assertEqual(self.cfg,self.original)
    def test_existing_secret_is_not_copied_or_replaced(self):
        self.cfg['patchClashConfig']['secret']='existing-private-token'
        before=copy.deepcopy(self.cfg)
        s.apply('apply')
        self.assertEqual(self.cfg['patchClashConfig']['secret'],'existing-private-token')
        self.assertNotIn('existing-private-token',s.STATE.read_text())
        s.apply('undo');self.assertEqual(self.cfg,before)
if __name__=='__main__':unittest.main(verbosity=2)
