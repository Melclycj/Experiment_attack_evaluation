"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from common import MAX_OUTPUT, identity, json_bytes, utc
from judge import aggregate_attempts, aggregate_targets, classify_target
from record import RunDirectory

RESERVE = 3 * 1024 * 1024
# Per-row result metadata bound. 16 KiB since v4: NB-23 has six process targets (the two row file workers added),
# and a failure-path row that keeps each target's stop witness exceeded 8 KiB (offline SignalBatch fixtures).
ROW_LIMIT = 16 * 1024


class Evidence:
    def __init__(self, directory):
        self.directory, self.counter = directory, 0

    def raw(self, data, suffix='json'):
        self.counter += 1
        name = f'raw-{self.counter:04d}.' + suffix
        self.directory.write(name, data, reserve=RESERVE)
        return {'file': name, **identity(data)}

    def commands(self, commands):
        output = []
        for item in commands:
            copy = {k: v for k, v in item.items() if k not in ('stdout', 'stderr')}
            for stream in ('stdout', 'stderr'):
                data = item.get(stream, '').encode('utf-8')
                if data:
                    copy[stream] = self.raw(data, suffix=stream)
            output.append(copy)
        return [self.raw(json_bytes(output), suffix="commands.json")]


def new_row(config, case, script):
    return {'attack': case.attack, 'config': config, 'kind': case.kind, 'script': script,
            'expected': case.expectation(config), 'observed': [], 'observed_mechanism': None,
            'mismatch': False, 'control': {'ok': False}, 'external_fact': [],
            'started_at': utc(), 'finished_at': utc(), 'attempts': [],
            'request_contract': 'unprepared:' + script['sha256'],
            **aggregate_attempts([], case.repeats)}


def failed_attempt(repeat, reason, targets=(), *, facts=None, evidence=None):
    results = [{'id': key, **classify_target(expected_mechanism='', observed_mechanism=None,
        target_verified=False, control_ok=False, complete=False, external_effect=None,
        external_fact={}, expected_observation=False, invalid_reason=reason)} for key in targets]
    # Reason must retain the actual stage failure even if identity is unverified.
    for t in results:
        candidate = (facts or {}).get(t['id'], {})
        t.update(external_effect=candidate.get('external_effect'),
                 external_fact=candidate.get('external_fact', {}),
                 target_verified=candidate.get('target_verified', False),
                 invalid_reason=reason, quality_issue=reason)
        # Quality remains invalid even when a pre-recovery witness proves effect.
    outcome, why = aggregate_targets(results)
    if not results:
        results = [{'id': 'preparation', 'outcome': 'invalid', 'invalid_reason': reason,
                    'external_fact': {}, 'complete': False, 'control': {'ok': False}}]
        outcome, why = aggregate_targets(results)
    result = {'repeat': repeat, 'targets': results, 'outcome': outcome, 'invalid_reason': why}
    if evidence is not None:
        result['evidence'] = evidence
    return result


def refresh(row):
    row.update(aggregate_attempts(row['attempts'], row['repeats']))
    row['finished_at'] = utc()
    references = [{'repeat': a['repeat'], 'evidence': a['evidence']}
                  for a in row['attempts'] if 'evidence' in a]
    row['observed'] = references
    row['external_fact'] = references
    row['control'] = {'ok': all(t.get('control', {}).get('ok') is True
                              for a in row['attempts'] for t in a['targets'])}
    mechanisms = sorted({t['observed_mechanism'] for a in row['attempts'] for t in a['targets']
                         if t.get('observed_mechanism')})
    row['observed_mechanism'] = ', '.join(mechanisms) or None
    row['mismatch'] = any(t.get('mismatch') for a in row['attempts'] for t in a['targets'])


def append(row, attempt, *, evidence=None):
    row['attempts'].append(attempt)
    refresh(row)
    if len(json_bytes(row)) > ROW_LIMIT:
        # Archive the exact pre-compaction record FIRST. If archival fails, keep
        # it in memory; record.validate_row refuses oversized final metadata.
        if evidence is None:
            raise ValueError('result metadata budget exceeded without archiver')
        receipt = evidence.raw(json_bytes(row), 'oversized-result.json')
        facts = {t['id']: {'external_effect': t.get('external_effect'),
                          'target_verified': t.get('target_verified', False),
                          'external_fact': {'evidence': receipt}}
                 for t in attempt['targets']}
        row['attempts'][-1] = failed_attempt(attempt['repeat'], 'result-metadata-budget',
            facts, facts=facts, evidence=receipt)
        refresh(row)
        # Budget/archival failure is quality invalid, not a validated success;
        # candidate effects and the full original result remain attributable.
        raise ValueError('result metadata budget exceeded; candidate archived')
