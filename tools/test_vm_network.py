#!/usr/bin/env python3
"""只模拟 pf/控制 API；不执行防火墙命令、不改变真实网络。"""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from core import vmnetwork

spec = importlib.util.spec_from_file_location('guard', ROOT/'tools/vm-network-guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def profile():
    return dict(version=1, interface='en0', tunInterface='utun0',
                allowedIPs=['8.8.8.8'], port=443, configHash=hashlib.sha256(b'config').hexdigest(),
                identity='a'*64, rulesHash='b'*64)


class VMTests(unittest.TestCase):
    def test_vm_blocks_ordinary_network_repair_after_authentication(self):
        import app
        for path in ('/api/ipv6', '/api/proxyfix', '/api/shellproxy', '/api/sessionapi'):
            handler = object.__new__(app.Handler)
            handler.path = path
            handler.headers = {'X-CClean-Privacy-Token': app.PRIVACY_TOKEN}
            with patch.object(vmnetwork, 'enabled', return_value=True), \
                 patch.object(handler, '_local_request', return_value=True), \
                 patch.object(handler, '_body', return_value={}), patch.object(handler, '_err') as error:
                handler._post()
                self.assertEqual(error.call_args.args[1], 409)

    def test_default_deny_covers_all_other_interfaces_and_ipv6(self):
        rules = guard.pf_rules(profile())
        self.assertTrue(rules.endswith('block drop out quick all\n'))
        self.assertIn('on en0 inet proto tcp to { 8.8.8.8 } port 443', rules)
        self.assertNotIn('inet6', rules)
        self.assertNotIn('proto tcp to any', rules)
        sealed = guard.pf_rules(profile(), sealed=True)
        self.assertNotIn('8.8.8.8', sealed)
        self.assertNotIn('inet proto tcp', sealed)
        self.assertIn('port 68 to { 255.255.255.255 } port 67', sealed)

    def test_policy_does_not_accept_interface_or_address_injection(self):
        for change in ({'interface':'en0 all\npass out all'}, {'allowedIPs':['any']},
                       {'allowedIPs':['127.0.0.1']}, {'tunInterface':'utun0, en1'},
                       {'allowedIPs':[]}, {'port':0}, {'port':'443; pass out all'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                guard.pf_rules({**profile(), **change})

    def test_rule_mode_requires_udp_reject_before_final_proxy(self):
        udp = dict(type='Network', payload='udp', proxy='REJECT')
        final = dict(type='Match', payload='', proxy='PROXY')
        self.assertTrue(guard.rules_valid([udp, final]))
        self.assertFalse(guard.rules_valid([final, udp]))
        self.assertFalse(guard.rules_valid([udp, {**final, 'proxy':'DIRECT'}]))
        self.assertFalse(guard.rules_valid([dict(type='GeoIP', payload='CN', proxy='DIRECT'), udp, final]))
        self.assertFalse(guard.rules_valid([dict(type='IPCIDR', payload='1.0.0.0/8', proxy='DIRECT'), udp, final]))
        self.assertTrue(guard.rules_valid([dict(type='IPCIDR', payload='10.0.0.0/8', proxy='DIRECT'), udp, final]))

    def test_rule_counters_do_not_change_policy_identity(self):
        a=[dict(type='Network', payload='udp', proxy='REJECT', extra={'hitCount':1,'hitAt':'old','disabled':False})]
        b=[dict(type='Network', payload='udp', proxy='REJECT', extra={'hitCount':99,'hitAt':'new','disabled':False})]
        self.assertEqual(guard.rules_identity(a),guard.rules_identity(b))
        b[0]['proxy']='DIRECT'
        self.assertNotEqual(guard.rules_identity(a),guard.rules_identity(b))

    def test_actual_proxy_chain_is_pinned_and_direct_rejected(self):
        nodes = {'PROXY':{'type':'Selector','now':'US-AUTO','all':['US-AUTO']},
                 'US-AUTO':{'type':'Fallback','now':'NodeA','all':['NodeA']},
                 'NodeA':{'type':'Http'}, 'NodeB':{'type':'Http'}}
        first = guard.selection(nodes)
        self.assertNotEqual(first, guard.selection({**nodes, 'US-AUTO':{'type':'Fallback','now':'NodeB','all':['NodeB']}}))
        with self.assertRaises(ValueError):
            guard.selection({**nodes, 'US-AUTO':{'type':'Fallback','now':'DIRECT','all':['DIRECT']}})
        with self.assertRaises(ValueError):
            guard.selection({**nodes, 'US-AUTO':{'type':'Fallback','now':'NodeA','all':['NodeA','NodeB']}})

    def test_audit_seals_when_proxy_fails_and_flushes_old_states(self):
        p = profile()
        sealed = guard.pf_rules(p, sealed=True)
        calls = []
        loads = []
        def run(args):
            calls.append(args)
            if args[1:6] == ['-o','none','-n','-v','-f']: return sealed
            if args[1:] == ['-s','info']: return 'Status: Enabled'
            if args[1:] == ['-s','Interfaces','-v']: return 'en0\nlo0 (skip)\nutun0'
            if args[1:] == ['-sr']: return 'anchor "com.vmproxy" quick all'
            if args[1:] == ['-a',guard.ANCHOR,'-sr']:
                return sealed if loads else 'pass out all'
            if args[1:6] == ['-o','none','-a',guard.ANCHOR,'-f']:
                loads.append(Path(args[-1]).read_text())
            return ''
        with patch.object(guard.os,'geteuid',return_value=0), \
             patch.object(guard,'secure_file',side_effect=[json.dumps(p),'config']), \
             patch.object(guard,'runtime',side_effect=RuntimeError('contains-secret')), \
             patch.object(guard,'run',side_effect=run), patch.object(guard,'atomic') as write:
            result = guard.audit()
        self.assertFalse(result['protected'])
        self.assertTrue(result['pfVerified'])
        self.assertEqual(loads,[sealed])
        self.assertIn(['/sbin/pfctl','-F','states'],calls)
        self.assertNotIn('contains-secret',json.dumps(write.call_args.args[1]))

    def test_status_requires_root_owner_freshness_and_typed_evidence(self):
        row=dict(version=1,at=time.time(),protected=True,pfVerified=True,udpBlocked=True,
                 identity='a'*64,policyHash='b'*64)
        with tempfile.TemporaryDirectory() as d:
            marker=Path(d)/'marker';marker.touch()
            path=Path(d)/'status'
            st=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_size=500)
            with patch.object(vmnetwork,'MARKER',marker), patch.object(vmnetwork,'STATUS',path), \
                 patch.object(Path,'lstat',return_value=st):
                path.write_text(json.dumps(row))
                self.assertTrue(vmnetwork.read()['protected'])
                st.st_uid=501
                self.assertFalse(vmnetwork.read()['checked'])
                st.st_uid=0;st.st_mode=stat.S_IFREG|0o666
                self.assertFalse(vmnetwork.read()['checked'])
                st.st_mode=stat.S_IFREG|0o644
                for change in ({'at':time.time()-40},{'protected':1},{'identity':''}):
                    path.write_text(json.dumps({**row,**change}))
                    self.assertFalse(vmnetwork.read()['checked'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
