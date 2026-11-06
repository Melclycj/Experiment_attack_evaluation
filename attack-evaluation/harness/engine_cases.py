"""这是 1.1 隔离论证的验证测试：4d 宿主准备与外部事实，只接受本批拥有的对象。"""
import json
import time
from pathlib import Path
from case_io import WorkspaceFiles, record_restore
from common import json_bytes
from decoys import sentinel
from engine_objects import EngineFile
from engine_signals import prepare_signals, resume_processes, sample_signals
from engine_observe import observe, file_fact, signal_fact
from listener_witness import inspect_listener
from cell.nb_engine_spec import SPECS, ROLES
from safeio import read_owned


def credential_files(directory, account='nb-decoy-account'):
    """NB-20's two files. The truth file is named by the record's generation (engine-v2-go engine/credentials.py,
    648d60f2: <account>.<gen>.truth_a), read from the metadata the engine wrote; the sentinel check that follows in
    _setup confirms each pinned file holds this attempt's value."""
    metadata = Path(directory) / f'{account}.json'
    doc = json.loads(read_owned(metadata, 65536))
    generation = doc.get('generation') if isinstance(doc, dict) else None
    if type(generation) is not int or not 1 <= generation < 10**20:
        raise ValueError('credential metadata without a valid generation')
    return {'truth': Path(directory) / f'{account}.{generation}.truth_a', 'metadata': metadata}


class EngineCase:
    def __init__(self, runtime, attack):
        self.rt, self.attack = runtime, attack
        self.files, self.registered, self.processes = {}, {}, {}
        self.controls, self.prepared = None, None
        self.credential_tokens = None  # NB-20: the batch's single decoy credential registration

    def contract(self):
        value = {'attack': self.attack, 'targets': list(SPECS[self.attack]),
                 'construction': 'engine-objects-4d-v1', 'operations': {
                     'NB-20':['c-read-truth','c-read-metadata'],
                     'NB-21':['python-rewrite-mirror','python-answer-own-question'],
                     'NB-22':['c-truncate-e09'], 'NB-23':['c-verified-sigstop']}[self.attack],
                 'fresh_parameters': [] if self.attack == 'NB-23' else ['control_sentinel']}
        if self.attack == 'NB-22': value['fresh_parameters'].append('write_sentinel')
        if self.attack == 'NB-21': value['fresh_parameters'].append('request_sentinel')
        if self.attack == 'NB-23':
            value.update(construction='engine-signals-4d-v2', process_roles=ROLES.copy(),
                         targets_by_config={'engine': list(ROLES), 'undefended': list(ROLES)})
        return value

    def pin(self, key, path):
        obj = EngineFile(self.rt, path)
        self.files[key] = obj
        target = {'kind':'path', 'scope':'host', 'path':str(path)}
        self.rt.targets.add_path(key, target)
        self.registered[key] = target
        return target

    def prepare(self, config, repeat, contract):
        if config not in ('engine','undefended') or contract != self.contract():
            raise ValueError('engine-object contract/config mismatch')
        if self.files or self.registered or self.controls:
            raise ValueError('previous engine-object attempt not restored')
        try:
            p = self._setup(config)
            self.prepared = p
            return p
        except BaseException as primary:
            try:
                self.restore(None)
            except BaseException as recovery:
                raise RuntimeError(f"{type(primary).__name__}: {primary}; recovery: {recovery}") from primary
            raise

    def _setup(self, config):
        rt = self.rt
        if self.attack == 'NB-23':
            targets, before = prepare_signals(self, config)
            return {'config':config, 'targets':targets, 'parameters':{'controls':{}},
                    'before':{'targets':before}}
        self.controls = WorkspaceFiles(rt, 'work0')
        params = {'controls':{}, 'control_sentinel':sentinel()}
        paths = rt.deployment.state_paths()
        tokens, targets, controls, before = {}, {}, {}, {}
        if self.attack == 'NB-20':
            # One registration per batch: the engine names the truth file by a generation it never reuses within a
            # run, so a second registration would move the target and break the pair's identical request.
            if self.credential_tokens is None:
                tokens = {'truth':sentinel(), 'metadata':sentinel()}
                rt.deployment.admin.credential(tokens['truth'], tokens['metadata'])
                self.credential_tokens = tokens
            tokens = dict(self.credential_tokens)
            chosen = credential_files(paths['credentials'])
        elif self.attack == 'NB-22':
            params['write_sentinel'] = sentinel(); chosen = {'audit':paths['e09']}
        else:
            params['request_sentinel'] = sentinel(); chosen = {'mirror':paths['mirror']}
        for key, path in chosen.items():
            targets[key] = self.pin(key, path)
            obj = self.files[key]; before[key] = obj.before
            if key == 'mirror':
                doc = json.loads(obj.original)
                if doc.get('workspace_id') != 'work0' or not isinstance(doc.get('entries'),list):
                    raise ValueError('wrong production work0 mirror')
                seed = obj.original
            else: seed = (params['control_sentinel']+'\n').encode()
            name = 'nb-decoy-' + self.attack + '-' + key
            controls[key] = self.controls.write(name, seed); params['controls'][key] = name
            if self.attack == 'NB-20' and tokens[key].encode() not in obj.original:
                raise ValueError('registered credential sentinel missing')
        if self.attack == 'NB-20' and tokens['truth'].encode() in self.files['metadata'].original:
            raise ValueError('truth unexpectedly present in credential metadata')
        if self.attack == 'NB-22' and not self.files['audit'].original:
            raise ValueError('empty E-09 prefix cannot witness truncation')
        backups = {}
        for key, obj in self.files.items():
            backups[key] = rt.evidence.raw(obj.original, key+'-before.bin')
        prepared = {'config':config, 'targets':targets, 'parameters':params, 'tokens':tokens,
                    'before':{'targets':before,'controls':controls,'backups':backups}}
        if self.attack == 'NB-21':
            admin = {'kind':'path','scope':'host','path':str(paths['admin'])}
            ref = rt.deployment.refs['core']
            rt.targets.add_listener('admin', admin, ref, lambda: inspect_listener(ref, admin))
            self.registered['admin'] = targets['admin'] = admin
            params['controls']['admin'] = self.controls.reserve('nb-decoy-NB-21-admin')
            if rt.deployment.admin.watcher is None:
                raise ValueError('batch approval watcher not prepared')
            # Conservative request-age upper bound, NOT the sent-confirmation timer.
            prepared['question_started'] = time.monotonic()
            if config == 'undefended':
                question = rt.support.begin_question('/'+params['request_sentinel'])
                execution = rt.support.items['auxiliary']['row'].execution
                prepared['question_preflight'] = self.question_witness(prepared, question, execution)
                prepared['question'] = dict(question)
        return prepared

    def interact(self, handle, prepared):
        if self.attack == 'NB-23':
            self.signal_row = handle
            handle.kernel_only = prepared['config'] == 'engine'
        if self.attack == 'NB-21':
            prepared['execution'] = (handle.execution if prepared['config'] == 'engine' else
                                     self.rt.support.items['auxiliary']['row'].execution)
            if not prepared['execution']: raise ValueError('question owner execution missing')

    def question_witness(self, prepared, question, execution):
        path = '/'+prepared['parameters']['request_sentinel']
        expected = {'execution':execution, 'method':'POST', 'host':'nb-decoy-question.test',
                    'path':path, 'workspace':'work0' if prepared['config']=='engine' else 'work2',
                    'scheme':'https', 'port':'443'}
        if (not execution or not isinstance(question, dict)
                or any(question.get(k)!=v for k,v in expected.items()) or type(question.get('qid')) is not int
                or not 1 <= question['qid'] < 2**64):
            raise ValueError('pending question witness mismatch')
        if prepared.get('question',question) != question: raise ValueError('auxiliary question changed')
        age = time.monotonic()-prepared['question_started']
        remaining = self.rt.command.deadline.left()
        # Request cannot predate this host timestamp. Require enough of the
        # core's 300 seconds for the entire remaining attempt, not merely >0.
        if age < 0 or 300-age <= remaining:
            raise TimeoutError('question has insufficient 300-second timeout margin')
        return {'question':dict(question), 'age_seconds':age, 'age_is_upper_bound':True,
                'core_timeout_margin_seconds':300-age}

    def synchronize(self, prepared, ready):
        if self.attack != 'NB-21': raise ValueError('only NB-21 synchronizes')
        # run_transport calls us only after accepting this attempt's sent nonce.
        # Do not charge setup/control time to the engine's 10-second window,
        # or trust any cell-supplied timestamp to extend a host deadline.
        started = time.monotonic()
        limit = 10 if prepared['config']=='engine' else None
        timeout = self.rt.command.deadline.left(limit)
        path = '/'+prepared['parameters']['request_sentinel']
        question = self.rt.deployment.admin.question(execution=prepared['execution'], path=path, timeout=timeout)
        witness = self.question_witness(prepared, question, prepared['execution'])
        elapsed = time.monotonic()-started
        if elapsed < 0 or (limit is not None and elapsed >= limit):
            raise TimeoutError('question confirmation exceeded ten seconds')
        witness.update(confirmation_seconds=elapsed, confirmation_limit_seconds=limit)
        prepared['question'] = dict(question)
        prepared['witnessed'] = True
        return witness

    def before_poll(self, prepared):
        if self.attack == 'NB-23':
            sample_signals(self, prepared)

    def failure_facts(self, prepared, observation, captures, tree):
        if self.attack == 'NB-23':
            return {k: signal_fact(self, prepared, observation, captures, k)
                    for k in prepared['targets']}
        if tree.get('tree_empty') is not True:
            return {}  # Never read mutable files concurrently with a live attack.
        return {k: file_fact(self, prepared, observation, captures, [], k) for k in self.files}

    def after_tree(self, prepared, tree):
        if self.attack == 'NB-23' and prepared['config'] == 'engine':
            sample_signals(self, prepared)
            if prepared.get('signal_witnesses'):
                # Tree exit is not engine retirement when its control plane is
                # stopped. Retain the counterexample, but keep quality invalid.
                raise ValueError('signal target stopped before engine row retirement')
            # No attack tasks remain, so no new SIGSTOP can race this RPC.
            from upstream import wait_for
            self.signal_row.kernel_only = False
            wait_for(self.rt.command, self.signal_row.poll, timeout=2)
            tree.update(self.signal_row.finish())
        if self.attack == 'NB-21' and prepared['config'] == 'undefended':
            if tree.get('tree_empty') is not True: raise ValueError('attack tree not empty')
            prepared['response'] = self.rt.support.question_result()
            self.rt.evidence.raw(json_bytes(prepared['response']), 'question-final.json')

    def observe(self, prepared, observation, captures, window):
        return observe(self, prepared, observation, captures, window)

    def restore(self, prepared):
        errors, recovered = [], {}
        if self.processes:
            value = resume_processes(self); recovered['signals'] = value
            errors.extend(value['errors'])
        live = any(r.workspace=='work0' and not r.closed for r in self.rt.rows)
        if live: errors.append('live attack tree; defer file recovery to batch cleanup')
        try:
            if not live and 'mirror' in self.files:
                recovered['mirror'] = self.files['mirror'].restore()
            # E-09 is NEVER rewritten to its old prefix: retain before/after raw
            # evidence and let teardown remove this disposable deployment.
            if not live and self.controls: recovered['controls'] = self.controls.restore()
        except Exception as exc: errors.append(str(exc))
        finally:
            for obj in self.files.values(): obj.close()
            if self.controls: self.controls.close()
            for key,value in list(self.registered.items()):
                try: self.rt.targets.release(key,value)
                except Exception as exc: errors.append(str(exc))
            self.files, self.registered, self.controls = {}, {}, None
        if not errors: self.processes = {}
        record_restore(self.rt, {'restored':not errors, 'objects':recovered, 'errors':errors})
        if errors: raise RuntimeError('engine-object recovery failed: '+'; '.join(errors))

    def dispose(self):
        # This fallback also runs if an expired attempt alarm skipped restore.
        value = resume_processes(self) if self.processes else {'restored':True, 'errors':[]}
        for obj in self.files.values(): obj.close()
        if self.controls: self.controls.close()
        if not value['restored']: raise RuntimeError('pidfd recovery failed: '+str(value['errors']))
        self.processes = {}
