"""离线报告回归：从结构化证据生成报告，不手改已有运行、不启动被测程序。"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from common import identity, json_bytes
from fixtures import header, row, target
from judge import finalize_pairing
from record import RunDirectory, load_run, render_readme
from report_view import batch_status, evidence_links, expectation
from run_evidence import Evidence, new_row
from run_registry import CASES, Case
from summarize import history, render_results


def completed():
    rows = finalize_pairing([row(), row('undefended')])
    for value in rows:
        value['expected'] = {'outcome': 'blocked' if value['config'] == 'engine' else 'succeeded'}
    return header(controller_error=None), rows


class ReportGenerationTests(unittest.TestCase):
    def test_expected_is_config_specific_for_all_registered_cases(self):
        for case in CASES.values():
            with self.subTest(attack=case.attack):
                a = new_row('engine', case, identity(b'script'))
                b = new_row('undefended', case, identity(b'script'))
                self.assertEqual(a['expected'], case.expected)
                expected = case.expected_by_config.get('undefended', {'outcome': 'succeeded'})
                self.assertEqual(b['expected'], expected)
                b['expected']['outcome'] = 'invalid'
                self.assertEqual(case.expectation('undefended'), expected)
                a['expected']['outcome'] = 'invalid'
                self.assertNotEqual(a['expected'], case.expected)

    def test_nb23_approved_target_exceptions_are_preserved_and_deepcopied(self):
        expected = {'outcome': 'succeeded', 'targets': {
            'core': 'stopped', 'spawner': 'identity-matched EPERM',
            'auxiliary': 'identity-matched EPERM', 'victim': 'identity-matched EPERM',
            'auxiliary-worker': 'identity-matched EPERM', 'victim-worker': 'identity-matched EPERM'}}
        case = CASES['NB-23']
        row = new_row('undefended', case, identity(b'script'))
        self.assertEqual(row['expected'], expected)
        row['expected']['targets']['core'] = 'invalid'
        self.assertEqual(case.expectation('undefended'), expected)

    def test_future_config_exception_is_explicit_and_not_shared(self):
        case = Case('NB-23', 'NB-23.py', lambda rt: None, {'outcome': 'blocked'},
                    expected_by_config={'undefended': {'outcome': 'blocked', 'mechanism': 'fixture'}})
        got = case.expectation('undefended')
        self.assertEqual(got['mechanism'], 'fixture')
        got.clear()
        self.assertTrue(case.expected_by_config['undefended'])
        with self.assertRaises(ValueError):
            case.expectation('unregistered')

    def test_late_support_error_is_visible_in_all_report_surfaces(self):
        h, rows = completed()
        h['controller_error'] = {'stage': 'ready', 'type': 'RuntimeError', 'message': 'support close failed: auxiliary'}
        self.assertEqual(batch_status(h, rows)['state'], 'failed')
        for rendered in (render_results(rows, h), render_readme(h, rows), history([(h, rows)])):
            self.assertIn('未完整结束', rendered)
            self.assertIn('support close failed: auxiliary', rendered)
        self.assertEqual(rows[0]['outcome'], 'blocked')
        self.assertEqual(rows[1]['outcome'], 'succeeded')

    def test_complete_clean_trial_not_misrepresented_as_formal(self):
        h, rows = completed()
        self.assertEqual(batch_status(h, rows)['state'], 'completed')
        self.assertIn('完整结束；试跑，不算数', render_results(rows, h))

    def test_formal_identity_does_not_hide_failed_batch(self):
        h, rows = completed()
        h.update(formal=True, controller_error={'message': 'late failure'})
        text = render_results(rows, h)
        self.assertIn('未完整结束', text)
        self.assertIn('正式身份已核对（不等于批次通过）', text)

    def test_cleanup_failure_is_independent_of_row_outcomes(self):
        h, rows = completed()
        h.update(cleanup={'ok': False}, cleanup_ok=False)
        self.assertEqual(batch_status(h, rows)['state'], 'failed')
        self.assertIn('清理未通过', render_results(rows, h))

    def test_missing_old_controller_status_is_unknown_not_passed(self):
        h, rows = completed()
        h.pop('controller_error')
        self.assertEqual(batch_status(h, rows)['state'], 'unknown')
        self.assertIn('未记录主控结束状态', render_results(rows, h))

    def test_failure_with_no_rows_remains_in_history(self):
        h = header(controller_error={'message': 'preflight failed'})
        text = history([(h, [])])
        self.assertIn(h['run'], text)
        self.assertIn('preflight failed', text)

    def test_mixed_success_and_invalid_target_cannot_look_clean(self):
        h, rows = completed()
        rows[1] = row('undefended', branches=[target(effect=True), target('bad', complete=False)])
        self.assertEqual(rows[1]['outcome'], 'succeeded')
        self.assertEqual(batch_status(h, rows)['state'], 'failed')

    def test_incomplete_repeat_schedule_is_not_complete_after_one_success(self):
        h, rows = completed()
        rows[1]['repeats'] = 2
        self.assertIn('计划重复未完成', render_results(rows, h))

    def test_outcome_mismatch_does_not_rewrite_valid_observation_or_execution(self):
        h, rows = completed()
        rows[1]['expected'] = {'outcome': 'blocked'}
        self.assertEqual(expectation(rows[1]), '判决不符')
        self.assertEqual(batch_status(h, rows)['state'], 'completed')
        self.assertIn('判决不符', render_results(rows, h))
        self.assertEqual(rows[1]['outcome'], 'succeeded')

    def test_mechanism_location_control_pairing_and_evidence_are_visible(self):
        h, rows = completed()
        rows[0]['expected'].update(mechanism='file-view', location='native/sandbox/child.c:pivot_root')
        receipt = {'file': 'raw-0001.json', **identity(b'receipt')}
        fact = {'file': 'raw-0002.file-fact.json', **identity(b'fact')}
        rows[0]['attempts'][0]['evidence'] = receipt
        rows[0]['attempts'][0]['targets'][0]['external_fact'] = {'evidence': fact}
        text = render_results(rows, h)
        for item in ('native/sandbox/child.c:pivot_root', '不是动态定位', 'file-view', '对照通过',
                     '身份核对', '配对前提', '[raw-0001.json](raw-0001.json)',
                     '[raw-0002.file-fact.json](raw-0002.file-fact.json)', '0.95', '不能外推'):
            self.assertIn(item, text)

    def test_report_escapes_error_and_never_links_untrusted_path(self):
        h, rows = completed()
        h['controller_error'] = {'message': '<script>|\nerror'}
        self.assertIn('&lt;script&gt;&#124;', render_results(rows, h))
        for name in ('../outside', 'https://remote/x', 'evil](link).json'):
            self.assertNotIn('](', evidence_links({'file': name, **identity(b'x')}))

    def test_persisted_report_roundtrips_and_load_rechecks_derivation(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, rows = completed()
            run = RunDirectory(Path(tmp), h['run'])
            run.finalize(h, rows)
            loaded, final = load_run(run.path)
            self.assertEqual(loaded['report']['version'], 2)
            self.assertEqual(loaded['report']['batch']['state'], 'completed')
            self.assertEqual((run.path / 'results.md').read_bytes(), render_results(final, loaded).encode())

    def test_wrong_render_rejected_even_if_archive_manifest_is_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, rows = completed()
            run = RunDirectory(Path(tmp), h['run'])
            run.finalize(h, rows)
            data = b'false success report'
            (run.path / 'results.md').write_bytes(data)
            path = run.path / 'COMPLETE.json'
            manifest = json.loads(path.read_bytes())
            manifest['files']['results.md'] = identity(data)
            path.write_bytes(json_bytes(manifest))
            with self.assertRaisesRegex(ValueError, 'derived report'):
                load_run(run.path)

    def test_wrong_batch_summary_rejected_even_if_archive_manifest_is_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, rows = completed()
            run = RunDirectory(Path(tmp), h['run'])
            run.finalize(h, rows)
            meta = json.loads((run.path / 'run.json').read_bytes())
            meta['report']['batch']['state'] = 'failed'
            data = json_bytes(meta)
            (run.path / 'run.json').write_bytes(data)
            path = run.path / 'COMPLETE.json'
            manifest = json.loads(path.read_bytes())
            manifest['files']['run.json'] = identity(data)
            path.write_bytes(json_bytes(manifest))
            with self.assertRaisesRegex(ValueError, 'summary disagrees'):
                load_run(run.path)

    def test_old_metadata_loads_without_rewriting_or_silently_fixing_expectation(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, rows = completed()
            rows[1]['expected'] = {'outcome': 'blocked', 'mechanism': 'file-view'}
            run = RunDirectory(Path(tmp), h['run'])
            run.finalize(h, rows)
            meta = json.loads((run.path / 'run.json').read_bytes())
            meta.pop('report')
            data = json_bytes(meta)
            (run.path / 'run.json').write_bytes(data)
            path = run.path / 'COMPLETE.json'
            manifest = json.loads(path.read_bytes())
            manifest['files']['run.json'] = identity(data)
            path.write_bytes(json_bytes(manifest))
            before = {p.name: p.read_bytes() for p in run.path.iterdir()}
            _, loaded = load_run(run.path)
            self.assertEqual(loaded[1]['expected']['outcome'], 'blocked')
            self.assertIn('判决不符', expectation(loaded[1]))
            self.assertEqual(before, {p.name: p.read_bytes() for p in run.path.iterdir()})

    def test_renderer_does_not_mutate_inputs(self):
        h, rows = completed()
        before = copy.deepcopy((h, rows))
        render_results(rows, h)
        render_readme(h, rows)
        history([(h, rows)])
        self.assertEqual((h, rows), before)
