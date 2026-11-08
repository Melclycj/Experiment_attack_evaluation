"""这是 1.1 隔离论证的验证测试：审查边界回归，仅内存与临时文件。"""
import base64
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from common import identity, json_bytes
from engine_observe import file_fact
from fixtures import row, target
from record import validate_row, load_run
from run_evidence import append, Evidence, ROW_LIMIT
import test_6_capture_quality as capture_quality
from batch_fixtures import Adapter, FakeRuntime, header, cases, patches
from run_batch import Batch


class UpstreamEncoding(unittest.TestCase):
    def exercise(self, requests=None, key='truth', capture=b''):
        a,p,obs,caps=capture_quality.CaptureQuality().fixture(key,data=capture)
        if requests is None:
            marker=p['tokens'][key].encode()
            requests=[{'payload_base64':base64.b64encode(marker).decode(),'bytes':len(marker)}]
        return file_fact(a,p,obs,caps,requests,key)

    def test_actual_https_body_encoding_preserves_candidate_for_both_tokens(self):
        for key in ('truth','metadata'):
            value=self.exercise(key=key)
            self.assertTrue(value['external_effect'])
            self.assertTrue(value['external_fact']['upstream_sentinel'])
            self.assertTrue(value['invalid_reason'])  # missing diagnostics still invalid

    def test_encoded_unrelated_body_is_not_a_hit(self):
        value=self.exercise([{'payload_base64':base64.b64encode(b'other').decode(),'bytes':5}])
        self.assertFalse(value['external_effect'])

    def test_bad_base64_is_quality_error_not_a_silent_zero(self):
        value=self.exercise([{'payload_base64':'###','bytes':1}])
        self.assertIn('upstream payload',value['invalid_reason'])
        self.assertFalse(value['external_effect'])

    def test_wrong_payload_length_does_not_prove_leak(self):
        marker=('nb-decoy-'+'x'*48).encode()
        value=self.exercise([{'payload_base64':base64.b64encode(marker).decode(),'bytes':1}])
        self.assertFalse(value['external_effect'])
        self.assertIn('upstream payload',value['invalid_reason'])

    def test_bad_record_does_not_hide_later_verified_hit(self):
        marker=('nb-decoy-'+'x'*48).encode()
        value=self.exercise([{'payload_base64':'###'},
                            {'payload_base64':base64.b64encode(marker).decode(),'bytes':len(marker)}])
        self.assertTrue(value['external_effect'])
        self.assertIn('upstream payload',value['invalid_reason'])

    def test_bad_payload_does_not_erase_valid_action_capture(self):
        marker=('nb-decoy-'+'x'*48).encode()
        value=self.exercise([{'payload_base64':None}],capture=marker)
        self.assertTrue(value['external_effect'])
        self.assertIn('upstream payload',value['invalid_reason'])

    def test_plain_metadata_hit_remains_supported(self):
        value=self.exercise([{'path':'/'+('nb-decoy-'+'x'*48)}])
        self.assertTrue(value['external_effect'])


class MetadataBudget(unittest.TestCase):
    def oversized(self):
        value=row(branches=[target(effect=True)])
        attempt=value['attempts'].pop()
        attempt['targets'][0]['external_fact']={'candidate':'witness','padding':'x'*(ROW_LIMIT+50)}
        return value,attempt

    def test_no_archiver_cannot_destructively_replace_candidate(self):
        value,attempt=self.oversized();before=deepcopy(attempt)
        with self.assertRaisesRegex(ValueError,'budget'):append(value,attempt)
        self.assertEqual(value['attempts'][-1],before)
        self.assertTrue(value['attempts'][-1]['targets'][0]['external_effect'])

    def test_oversize_cannot_be_finalized_as_unbounded_metadata(self):
        value,attempt=self.oversized();value['attempts']=[attempt]
        with self.assertRaisesRegex(ValueError,'budget'):validate_row(value)

    def test_archive_before_compaction_and_preserve_effect_candidate(self):
        value,attempt=self.oversized();raw=[]
        def archive(data,suffix):
            raw.append(json.loads(data));return {'file':'raw-0001.json',**identity(data)}
        from types import SimpleNamespace
        with self.assertRaisesRegex(ValueError,'budget'):
            append(value,attempt,evidence=SimpleNamespace(raw=archive))
        self.assertEqual(raw[0]['attempts'][-1]['outcome'],'succeeded')
        t=value['attempts'][-1]['targets'][0]
        self.assertEqual(t['outcome'],'invalid');self.assertTrue(t['external_effect'])
        self.assertEqual(t['external_fact']['evidence']['file'],'raw-0001.json')
        self.assertLessEqual(len(json_bytes(value)),ROW_LIMIT)
        validate_row(value)

    def test_archive_failure_preserves_in_memory_original(self):
        value,attempt=self.oversized();before=deepcopy(attempt)
        from types import SimpleNamespace
        def fail(*a):raise OSError('archive full')
        with self.assertRaisesRegex(OSError,'archive full'):
            append(value,attempt,evidence=SimpleNamespace(raw=fail))
        self.assertEqual(value['attempts'][-1],before)

    def test_prior_success_not_overwritten_by_later_oversize(self):
        value,attempt=self.oversized();value['repeats']=2
        first=deepcopy(attempt);first['targets'][0]['external_fact']={'small':True}
        value['attempts']=[first];attempt['repeat']=2
        from types import SimpleNamespace
        with self.assertRaisesRegex(ValueError,'budget'):
            append(value,attempt,evidence=SimpleNamespace(raw=lambda d,s:{'file':'raw.json',**identity(d)}))
        self.assertEqual(value['outcome'],'succeeded');self.assertEqual(value['successes'],1)
        self.assertTrue(value['attempts'][1]['targets'][0]['external_effect'])

    def test_batch_archives_candidate_and_stops_following_case(self):
        class Oversized(Adapter):
            def observe(self,*args):
                result=super().observe(*args)
                for f in result.values():
                    f['external_effect']=True
                    f['external_fact']['padding']='x'*(ROW_LIMIT+50)
                return result
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp,ExitStack() as stack:
            chosen=cases();chosen[0]=replace(chosen[0],factory=lambda rt:Oversized(rt,chosen[0].attack))
            rt=FakeRuntime(Path(tmp),chosen);patches(rt,stack)
            batch=Batch(rt,chosen,['engine','undefended'],header(rt))
            self.assertEqual(batch.execute(),1)
            meta,rows=load_run(rt.evidence.directory.path)
            self.assertTrue(meta['cleanup_ok'])
            self.assertTrue(rows[0]['attempts'][0]['targets'][0]['external_effect'])
            self.assertIn('budget',rows[0]['invalid_reason'])
            self.assertIn('not-started',rows[1]['invalid_reason'])
            self.assertTrue(list(rt.evidence.directory.path.glob('*oversized-result.json')))
