"""这是 2.3 凭据使用绑定的验证测试：CB-14 条款 8 的离线测试。判官 fixtures 证明它能区分正确 engine（第二帧另开连接 →
blocked）与忽略账户复用的变体（第二帧骑上账户 A 的连接 → succeeded），并验证变体补丁锚点就位、补丁后仍可编译。
纯离线：不起 engine、上游、网络或容器。"""
import ast
import base64
from pathlib import Path
import tempfile
import unittest

from cb_keep_judge import keep_judge
from cb_judge import verdict
from cb_sentinels import new_credential
from cb_keep_variant import ANCHOR_KEY, ANCHOR_STORE, INJECT_KEY, INJECT_STORE, transform, prepare_variant
from build import inventory

SOURCE = Path(__file__).resolve().parents[6] / 'ExperimentLab/engine-v2-go'
KEEP_HOST = 'nb-decoy-cb-x.test'
AUTH = '/nb-decoy-cb/keep/auth/n'
PROBE = '/nb-decoy-cb/keep/probe/n'


def account():
    return new_credential('nb-decoy-A-' + 'a' * 12, KEEP_HOST, 8443, 'api-key')


def record(conn_id, path, *, had_auth, conn_authed, head=b'GET / HTTP/1.1\r\n\r\n'):
    return {'kind': 'keep-request', 'conn_id': conn_id, 'path': path, 'had_auth': had_auth,
            'conn_authed': conn_authed, 'head_base64': base64.b64encode(head).decode()}


def run_judge(records, config, a=None):
    a = a or account()
    spec = {'source': 'A', 'mechanism': 'connection-account-isolation'}
    parameters = {'path': AUTH, 'probe_path': PROBE}
    fact = keep_judge(spec, parameters, {'A': a}, {'complete': True}, {}, {'keep_requests': records},
                      config=config, coverage={'complete': True, 'gaps': [], 'forbidden': []})
    return fact, verdict(fact, key='api-key-reuse', expected=spec['mechanism'])


class KeepJudge(unittest.TestCase):
    def test_engine_isolated_second_connection_blocks(self):
        fact, v = run_judge([record(1, AUTH, had_auth=True, conn_authed=False),
                             record(2, PROBE, had_auth=False, conn_authed=False)], 'engine')
        self.assertFalse(fact['effect'])
        self.assertEqual(v['outcome'], 'blocked')
        self.assertEqual(v['observed_mechanism'], 'connection-account-isolation')

    def test_engine_reused_connection_succeeds(self):
        fact, v = run_judge([record(7, AUTH, had_auth=True, conn_authed=False),
                             record(7, PROBE, had_auth=False, conn_authed=True)], 'engine')
        self.assertTrue(fact['effect'])
        self.assertEqual(v['outcome'], 'succeeded')

    def test_undefended_single_connection_is_prerequisite(self):
        fact, v = run_judge([record(3, AUTH, had_auth=True, conn_authed=False),
                             record(3, PROBE, had_auth=False, conn_authed=True)], 'undefended')
        self.assertTrue(fact['effect'])
        self.assertEqual(v['outcome'], 'succeeded')
        self.assertTrue(v['prerequisite_ok'])

    def test_probe_carrying_a_credential_is_invalid(self):
        fact, v = run_judge([record(1, AUTH, had_auth=True, conn_authed=False),
                             record(2, PROBE, had_auth=True, conn_authed=False)], 'engine')
        self.assertIn('keep-probe-frame-carried-credential', fact['quality_issue'])
        self.assertEqual(v['outcome'], 'invalid')

    def test_secret_in_probe_head_is_an_effect(self):
        a = account()
        head = b'GET ' + PROBE.encode() + b' HTTP/1.1\r\nx-leak: ' + a.truth + b'\r\n\r\n'
        records = [record(1, AUTH, had_auth=True, conn_authed=False),
                   record(2, PROBE, had_auth=False, conn_authed=False, head=head)]
        fact, v = run_judge(records, 'engine', a=a)
        self.assertTrue(fact['forbidden'])
        self.assertTrue(fact['effect'])
        self.assertEqual(v['outcome'], 'succeeded')

    def test_missing_probe_frame_is_invalid(self):
        fact, v = run_judge([record(1, AUTH, had_auth=True, conn_authed=False)], 'engine')
        self.assertIn('keep-frame-count', fact['quality_issue'])
        self.assertEqual(v['outcome'], 'invalid')


class KeepVariant(unittest.TestCase):
    def test_current_source_transforms_without_importing_engine(self):
        patched = transform((SOURCE / 'connector/upstream.py').read_bytes())
        self.assertEqual(patched.count(INJECT_KEY.encode()), 1)
        self.assertEqual(patched.count(INJECT_STORE.encode()), 1)
        self.assertEqual(patched.count(ANCHOR_KEY.encode()), 0)  # the account-keyed reuse lookup is gone
        ast.parse(patched)

    def test_drift_and_second_patch_fail_closed(self):
        source = (SOURCE / 'connector/upstream.py').read_bytes()
        for data in (b'pass\n', source.replace(ANCHOR_KEY.encode(), b''), transform(source)):
            with self.assertRaises(ValueError):
                transform(data)

    def test_exclusive_snapshot_keeps_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            (source / 'connector').mkdir(parents=True)
            (source / 'connector/upstream.py').write_bytes((SOURCE / 'connector/upstream.py').read_bytes())
            before = inventory(source)
            parent = base / 'nb-decoy-keep-variant'
            parent.mkdir()
            receipt = prepare_variant(source, parent / 'engine')
            self.assertEqual(inventory(source), before)
            self.assertFalse(receipt['formal'])
            self.assertEqual(receipt['variant'], 'connection-ignore-account')


if __name__ == '__main__':
    unittest.main()
