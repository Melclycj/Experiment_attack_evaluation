"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import time
import copy
import sys
from common import identity, json_bytes, utc
from judge import aggregate_targets, classify_configured_target, request_contract
from run_config import schedule
from report_view import batch_status
from run_contract import targets_for, validate_contract
from run_evidence import append, failed_attempt, new_row
from run_limits import alarm, until
from run_transport import CollectionError, collect, prepare_request, request, synchronize


class Batch:
    def __init__(self, runtime, cases, configs, header):
        self.rt, self.cases, self.configs, self.header = runtime, cases, configs, header
        self.contracts, self.adapters, self.rows = {}, {}, []
        for cfg, case in schedule(cases, configs):
            script = runtime.bundle['script_identities'][case.attack]
            self.rows.append(new_row(cfg, case, script))
        self.error, self.bindings = None, {}
        self.failure_context = {}

    def attempt(self, case, config, repeat):
        self.failure_context = {}
        end = min(self.rt.work_end, time.monotonic() + 30)
        if not case.branches:
            return self.attempt_row(case, config, repeat, end)
        # Each alias gets its own control, row/tree exit, one-second window,
        # external snapshot and restoration. Never attribute a final shared
        # inode change to both paths. Both still share R=1 and 30 seconds total.
        results, evidence, fatal = [], [], ''
        for key in case.branches:
            if fatal:
                part = failed_attempt(repeat, 'not-started: ' + fatal, [key])
            else:
                try:
                    part = self.attempt_row(case, config, repeat, end, key)
                except BaseException as exc:
                    fatal = type(exc).__name__ + ': ' + str(exc)[:512]
                    part = self.failed(repeat, fatal, [key])
            results.extend(part['targets'])
            if 'evidence' in part:
                evidence.append({'target': key, 'evidence': part['evidence']})
            fatal = fatal or part.get('fatal_error', '')
        outcome, reason = aggregate_targets(results)
        raw = self.rt.evidence.raw(json_bytes({'path_rows': evidence, 'targets': results}))
        return {'repeat': repeat, 'targets': results, 'outcome': outcome,
                'invalid_reason': reason, 'fatal_error': fatal, 'evidence': raw}

    def attempt_row(self, case, config, repeat, end, branch=None):
        rt = self.rt
        prepared, handle = None, None
        self.failure_context = {}
        before, tree, facts, req = {}, {}, {}, None
        observed, captures, collected = {}, {}, False
        old_deadline = rt.command.deadline
        rt.command.deadline = until(end)
        try:
            with alarm(end):
                adapter = self.adapters[case.attack]
                contract = self.contracts[case.attack]
                if branch is None:
                    prepared = adapter.prepare(config, repeat, copy.deepcopy(contract))
                else:
                    prepared = adapter.prepare_branch(config, repeat, copy.deepcopy(contract), branch)
                row_contract = {**contract, 'targets': [branch]} if branch else contract
                if set(prepared['targets']) != set(targets_for(row_contract, config)):
                    raise ValueError('prepared target branches differ from declared applicability')
                binding = {'targets': rt.paired_targets(prepared['targets'], row_contract),
                           'parameters': prepared['parameters']}
                # Sentinel values are per-attempt; exclude ONLY explicitly declared
                # fresh fields, checking they really are generated decoy strings.
                fresh = contract.get('fresh_parameters', [])
                stable = dict(binding['parameters'])
                for key in fresh:
                    value = stable.pop(key)
                    if not isinstance(value, str) or not value.startswith('nb-decoy-') or len(value) < 40:
                        raise ValueError('invalid per-attempt sentinel')
                binding = {'targets': binding['targets'], 'parameters': stable}
                binding_key = (case.attack, branch)
                previous = self.bindings.get(binding_key)
                if previous is not None:
                    if (previous['parameters'] != binding['parameters'] or any(
                            previous['targets'][key] != value for key, value in binding['targets'].items()
                            if key in previous['targets'])):
                        raise ValueError('cross-configuration target/action request changed')
                    binding['targets'] = {**previous['targets'], **binding['targets']}
                self.bindings[binding_key] = copy.deepcopy(binding)
                before = rt.targets.verify(prepared['targets'])
                if config == 'undefended':
                    rt.paths_accessible(prepared['targets'])
                req = request(rt.bundle['run'], config, case, repeat, prepared)
                prepared['request'] = req
                prepare_request(rt.work, req)
                rt.deployment.upstream.begin(req['sync']['nonce'])
                handle = rt.start(config, seconds=rt.command.deadline.left(30))
                adapter.interact(handle, prepared)  # explicit attach/support actions, never a verdict
                sync_fact = None
                while True:
                    before_poll = getattr(adapter, 'before_poll', None)
                    if before_poll is not None:
                        before_poll(prepared)
                    rt.pump()
                    if case.sync and sync_fact is None:
                        sync_fact = synchronize(rt.work, req, case.sync,
                            lambda ready: adapter.synchronize(prepared, ready))
                    if handle.poll():
                        break
                if before_poll is not None:
                    before_poll(prepared)
                tree = handle.finish()
                if case.sync and sync_fact is None:
                    raise ValueError('required synchronization did not happen')
                # NB-21 waits for the auxiliary POST's final result BEFORE closing
                # the external window. Other cases have no extra lifecycle hook.
                after_tree = getattr(adapter, 'after_tree', None)
                if after_tree is not None:
                    after_tree(prepared, tree)
                # No external effect window until kernel tree/lifecycle barrier.
                window = rt.deployment.upstream.end()
                rt.evidence.raw(json_bytes({'window': window, 'tree': tree}))
                observation_error = ''
                try:
                    collected = True
                    observed, captures = collect(rt.work, req, rt.evidence)
                except (ValueError, OSError) as exc:
                    observation_error = type(exc).__name__ + ': ' + str(exc)[:512]
                    observed, captures = {'complete': False, 'control_ok': False, 'error': observation_error}, {}
                    if isinstance(exc, CollectionError):
                        observed, captures = exc.observation or observed, exc.captures
                if observed.get('complete') is not True or observed.get('error') is not None:
                    observation_error = observation_error or 'incomplete-runner-observation'
                if tree.get('runner_ok') is False:
                    observation_error = observation_error or 'nonzero-runner-exit'
                complete = observed.get('complete') is True and not observation_error
                facts = adapter.observe(prepared, observed, captures, window)
                if set(facts) != set(prepared['targets']):
                    raise ValueError('host judge omitted/added a target')
                targets = []
                for key, fact in facts.items():
                    fact = dict(fact)
                    prerequisite = fact.pop('prerequisite_ok', False)
                    # Controller owns quality gates. Host adapter owns effects and
                    # mechanism interpretation; cell-provided booleans can't win.
                    fact.update(target_verified=True, complete=complete,
                                control_ok=observed['control_ok'] and fact.get('control_ok') is True)
                    if observation_error:
                        fact['invalid_reason'] = observation_error
                    result = classify_configured_target(config=config, attack=case.attack, key=key,
                        prerequisite_ok=prerequisite, **fact)
                    result.update(id=key, prerequisite_ok=prerequisite is True and result['outcome'] != 'invalid')
                    targets.append(result)
                outcome, reason = aggregate_targets(targets)
                receipt = {'request': req, 'before': before, 'prepared': prepared['before'],
                           'tree': tree, 'synchronization': sync_fact, 'window': window,
                           'observation': observed, 'targets': targets}
                raw = rt.evidence.raw(json_bytes(receipt))
                self.failure_context = {'facts': {t['id']: t for t in targets}, 'evidence': raw}
                fatal = observation_error or '; '.join(t['invalid_reason'] for t in targets
                                                       if t['outcome'] == 'invalid')
                return {'repeat': repeat, 'targets': targets, 'outcome': outcome,
                        'invalid_reason': reason, 'evidence': raw, 'fatal_error': fatal}
        except BaseException as primary:
            # No extra attempt time, no replay, and never snapshot a live writer.
            # Already sampled process facts survive even when this budget expired.
            candidates = dict(facts)
            if prepared:
                for key, value in prepared.get('signal_witnesses', {}).items():
                    candidates[key] = {'external_effect': True,
                                       'external_fact': {'stopped_witness': value,
                                           'stopped_evidence': prepared.get('signal_evidence', {}).get(key)}}
                try:
                    with alarm(end):
                        if tree.get('tree_empty') is True and req is not None and not collected:
                            try:
                                observed, captures = collect(rt.work, req, rt.evidence)
                            except (ValueError, OSError) as exc:
                                if isinstance(exc, CollectionError):
                                    observed, captures = exc.observation or {}, exc.captures
                        fallback = getattr(adapter, 'failure_facts', None)
                        if fallback is not None:
                            for key, value in fallback(prepared, observed, captures, tree).items():
                                if candidates.get(key, {}).get('external_effect') is not True:
                                    candidates[key] = value
                except BaseException:
                    pass  # Original failure stays primary; unknown is not false.
            self.failure_context = {'facts': {key: {**value, 'target_verified': key in before}
                                             for key, value in candidates.items()}}
            try:
                with alarm(end):
                    self.failure_context['evidence'] = rt.evidence.raw(json_bytes({
                        'error': str(primary)[:512], 'request': req, 'tree': tree,
                        'observation': observed, 'candidates': self.failure_context['facts']}),
                        'failure-before-restore.json')
            except BaseException:
                pass  # Bounded final result still carries previously pinned facts.
            raise
        finally:
            # Don't continue after a failed attempt; batch cleanup owns any live
            # tree. Restoration must be bounded and precede another attempt.
            primary = sys.exc_info()[1]
            try:
                if prepared is not None:
                    with alarm(end):
                        self.adapters[case.attack].restore(prepared)
            except BaseException as recovery:
                if primary is not None:
                    raise RuntimeError(f"{type(primary).__name__}: {primary}; "
                                       f"recovery: {recovery}") from primary
                raise
            finally:
                rt.command.deadline = old_deadline

    def failed(self, repeat, reason, targets):
        return failed_attempt(repeat, reason, targets, **self.failure_context)

    def after_cleanup(self):
        """Unit hook after engine exit and archives; 1.1 adds nothing here."""

    def execute(self):
        rt = self.rt
        try:
            with alarm(rt.work_end):
                rt.prepare()
                for case in self.cases:
                    adapter = case.factory(rt)
                    contract = adapter.contract()
                    validate_contract(contract, case.attack)
                    if case.branches and tuple(contract['targets']) != case.branches:
                        raise ValueError('per-path registry differs from contract')
                    self.adapters[case.attack], self.contracts[case.attack] = adapter, copy.deepcopy(contract)
                for row, (config, case) in zip(self.rows, schedule(self.cases, self.configs)):
                    row['request_contract'] = request_contract(self.contracts[case.attack])
                    row['applicable_targets'] = targets_for(self.contracts[case.attack], config)
                    if time.monotonic() >= rt.work_end:
                        raise TimeoutError('540-second work cutoff')
                    if rt.active != config:
                        rt.arm(config)
                    for repeat in range(1, case.repeats + 1):
                        try:
                            attempt = self.attempt(case, config, repeat)
                        except BaseException as exc:
                            reason = type(exc).__name__ + ': ' + str(exc)[:512]
                            append(row, self.failed(repeat, reason, row['applicable_targets']), evidence=rt.evidence)
                            raise
                        append(row, attempt, evidence=rt.evidence)
                        # Preserve the failed attempt, then stop, without creating
                        # a duplicate repeat. Pairing is applied only at finalize.
                        if attempt.get('fatal_error'):
                            raise ValueError('attempt quality failure: ' + attempt['fatal_error'])
                if hasattr(rt, 'finish_work'):
                    rt.finish_work()
        except BaseException as exc:
            self.error = {'stage': rt.stage, 'type': type(exc).__name__, 'message': str(exc)[:512]}
        finally:
            for adapter in self.adapters.values():
                dispose = getattr(adapter, 'dispose', None)
                if dispose is not None:
                    try:
                        dispose()
                    except Exception as exc:
                        self.error = self.error or {'stage': 'adapter-dispose', 'type': type(exc).__name__, 'message': str(exc)[:512]}
            try:
                with alarm(rt.end):
                    cleanup = rt.close()
            except BaseException as exc:
                cleanup = {'ok': False, 'failures': [{'step': 'controller-cleanup',
                           'error': type(exc).__name__ + ': ' + str(exc)[:512]}],
                           'retained': [str(p) for p in rt.resources.roots]}
            self.header.update(engine=rt.engine_identity, host=rt.host, cleanup=cleanup,
                               finished_at=utc(), controller_error=self.error)
            if rt.deployment:
                self.header['deployment'] = {'digest': rt.deployment.manifest.get('digest')}
                self.header['policy'] = {k: rt.deployment.manifest.get(k) for k in ('policy_digest', 'compiled_policy')}
            try:
                if rt.deployment and rt.deployment.manifest:
                    self.header['deployment']['manifest'] = rt.evidence.raw(json_bytes(rt.deployment.manifest))
                if rt.deployment and rt.deployment.evidence_bytes is not None:
                    self.header['e09'] = rt.evidence.raw(rt.deployment.evidence_bytes, 'e09.jsonl')
                self.header['commands'] = rt.evidence.commands(rt.records)
                measurement = getattr(rt.deployment,'cb_measure',None)
                if measurement is not None:
                    self.header['measurement'] = measurement.archive(rt.evidence)
                    if not self.header['measurement']['complete']:
                        self.error = self.error or {'stage':'connector-measurement',
                            'type':'IncompleteCoverage','message':str(measurement.errors)[:512]}
                        self.header['controller_error'] = self.error
                self.after_cleanup()
            except Exception as exc:
                self.header['evidence_error'] = str(exc)[:512]
                self.error = self.error or {'stage': 'evidence', 'type': type(exc).__name__, 'message': str(exc)[:512]}
                self.header['controller_error'] = self.error
            # Explicitly account for every unstarted or unfinished planned row.
            for row in self.rows:
                if not row['attempts']:
                    reason = 'not-started: ' + str(self.error or 'batch interrupted')[:512]
                    append(row, failed_attempt(1, reason), evidence=rt.evidence)
            self.header['finished_at'] = utc()
            final_rows = self.rt.evidence.directory.finalize(self.header, self.rows)
        # A real effect remains succeeded even alongside an invalid sibling.
        # Exit status is BATCH QUALITY, not that aggregate effect: use the
        # same per-target/repetition/pairing/cleanup gate as the saved report.
        return 0 if batch_status(self.header, final_rows)['state'] == 'completed' else 1
