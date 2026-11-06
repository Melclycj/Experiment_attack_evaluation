"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import hashlib
import os
import secrets
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).absolute().parent / 'cell'))
from common import identity, json_bytes
from cell.nb_contract import REQUEST, decode, stem, target, validate_request
from cell.nb_io import Files, PublicationPending
from decoys import synchronization, snapshot
from safeio import read_beneath

ALIASES = ('source', 'mount')


def workspace_entry(rt, name, config=None):
    """The arm's workspace: the deployment's v4 ones for engine, the host user's own for undefended (tests.md 1.7).
    No arm given means the runtime's current one (Runtime.use; set before any attempt)."""
    config = config if config is not None else getattr(rt, 'config', None) or 'engine'
    if config not in ('engine', 'undefended'):
        raise ValueError('unknown workspace arm')
    table = rt.deployment.workspaces if config == 'engine' else rt.deployment.host_workspaces
    if name not in table:
        raise ValueError(f'no {config} workspace {name}')
    return table[name]


def logical_target(rt, value):
    """Cross-configuration binding (run_batch): a host path inside an arm's workspace is the same logical object in
    both arms (workspace, alias, relative path), as a pinned process is its role. Other values are unchanged."""
    if not isinstance(value, dict) or value.get('kind') != 'path' or value.get('scope') != 'host':
        return value
    path = Path(value['path'])
    deployment = getattr(rt, 'deployment', None)
    for table in (getattr(deployment, 'workspaces', {}), getattr(deployment, 'host_workspaces', {})):
        for name, entry in table.items():
            for alias in ALIASES:
                root = entry.get(alias) if isinstance(entry, dict) else None
                if root is not None and (path == Path(root) or Path(root) in path.parents):
                    return {'kind': 'path', 'scope': 'workspace', 'workspace': name, 'alias': alias,
                            'path': path.relative_to(Path(root)).as_posix()}
    return value


def directory_owner(fd):
    """The owner a new workspace object takes: its directory's. Deployment decides the directories' owners: the v4
    workspace owner in the engine arm (the idmapped mount maps it to the row's uid in the cell), the host user in the
    undefended arm and the decoy home. Before v4 every object was given the host user, which a v4 cell cannot read."""
    info = os.fstat(fd)
    return info.st_uid, info.st_gid


class OwnedTargets:
    """Registration comes from trusted preparation, never from the cell request.
    Every claim is tied to an exact newly owned tree or a pinned owned process.
    Listener checks are supplied by the reviewed host adapter (socket tables,
    not a connect probe). A mere nb-decoy prefix is never sufficient.
    """
    def __init__(self, runtime):
        self.runtime, self.items = runtime, {}

    def add_path(self, key, value, *, workspace="work0", owner="attack", config=None):
        target(value)
        if value['kind'] != 'path':
            raise ValueError('path target required')
        if workspace not in ('work0', 'work1', 'work2'):
            raise ValueError('unknown target workspace')
        root = (self.runtime.work if workspace == 'work0' and config is None
                else workspace_entry(self.runtime, workspace, config)['mount'])
        path = (root / value['path'] if value['scope'] == 'work' else Path(value['path']))
        if not any(path == root or root in path.parents for root in self.runtime.resources.roots):
            raise ValueError('target is not in an exact registered run root')
        check = lambda: snapshot(path)
        before = check()
        if not before.get('exists'):
            raise ValueError('target must exist before the attempt')
        self._add(key, value, before, check, ('dev', 'ino', 'uid', 'mode'), owner=owner)

    def add_process(self, key, ref):
        if ref not in self.runtime.deployment.refs.values():
            raise ValueError('process reference not owned by this deployment')
        before = ref.read()
        value = {'kind': 'process', 'pid': before['pid'], 'starttime': before['start_time']}
        self._add(key, value, before, ref.read, ('pid', 'start_time', 'uids', 'cgroup'))

    def add_listener(self, key, value, ref, inspect):
        target(value)
        if value['kind'] not in ('inet', 'abstract', 'path') or ref not in self.runtime.deployment.refs.values():
            raise ValueError('listener needs a pinned, owned service reference')
        def check():
            full = ref.read()
            process = {k: full[k] for k in ('pid', 'start_time', 'uids', 'cgroup')}
            fact = inspect()  # adapter reads the pinned netns socket table
            if not fact or fact.get('listening') is not True or fact.get('target') != value:
                raise ValueError('external socket-table witness missing/mismatched')
            return {'process': process, 'socket': fact}
        before = check()
        self._add(key, value, before, check, ('process', 'socket'))

    @staticmethod
    def slot(key, owner):
        if owner not in ('attack', 'support') or not isinstance(key, str):
            raise ValueError('unknown target registration owner/key')
        return key if owner == 'attack' else (owner, key)

    def _add(self, key, value, before, check, fields, *, owner='attack'):
        key = self.slot(key, owner)
        if key in self.items and self.items[key][0] != value:
            raise ValueError('cannot rebind a target name to a different object descriptor')
        target(value)
        self.items[key] = (decode(json_bytes(value)), before, check, fields)

    def release(self, key, value, *, owner='attack'):
        key = self.slot(key, owner)
        if key not in self.items or self.items[key][0] != value:
            raise ValueError('release does not match registered target')
        del self.items[key]

    def verify(self, targets, *, owner='attack'):
        if not targets:
            raise ValueError('empty target set')
        facts = {}
        for name, value in targets.items():
            key = self.slot(name, owner)
            if key not in self.items or value != self.items[key][0]:
                raise ValueError('request target not registered for this run: ' + name)
            _, before, check, fields = self.items[key]
            now = check()
            if any(now.get(k) != before.get(k) for k in fields):
                raise ValueError('registered target identity changed: ' + name)
            facts[name] = now
        return facts


def publish(files, name, data, *, replace_request=False):
    """Pinned workspace write, chown BEFORE publication, no symlink traversal.
    Only fixed request may be replaced, after caller proves the previous tree empty.
    The file takes its directory's owner (v4 workspace owner or host user; directory_owner).
    """
    from cell.nb_contract import leaf
    leaf(name)
    if replace_request:
        if name != REQUEST:
            raise ValueError('only the fixed request may be replaced')
        try:
            os.unlink(name, dir_fd=files.fd)
        except FileNotFoundError:
            pass
    else:
        files.absent(name)
    uid, gid = directory_owner(files.fd)
    temp = '.nb-write-' + secrets.token_hex(16)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=files.fd)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchown(f.fileno(), uid, gid)
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.link(temp, name, src_dir_fd=files.fd, dst_dir_fd=files.fd, follow_symlinks=False)
    finally:
        os.unlink(temp, dir_fd=files.fd)
    os.fsync(files.fd)


def request(run, config, case, repeat, prepared):
    result = {'v': 1, 'run': run, 'config': config, 'attack': case.attack, 'repeat': repeat,
              'targets': prepared['targets'], 'parameters': prepared['parameters'],
              'sync': synchronization(run, config, case.attack, repeat)}
    return validate_request(result)


def prepare_request(work, req):
    files = Files(work)
    try:
        for name in (stem(req) + '-observed.json', req['sync']['ready'], req['sync']['release']):
            files.absent(name)
        publish(files, REQUEST, json_bytes(req), replace_request=True)
    finally:
        files.close()


def synchronize(work, req, state, observe):
    """Called while the row is live; no release without host observation.
    Returning None means readiness has not yet appeared, not permission to skip it.
    """
    with_files = Files(work)
    try:
        # A live mailbox can briefly have two links during exclusive publish.
        # Do not read that inode; retry only this condition under Batch's clock.
        try:
            ready = decode(with_files.read(req['sync']['ready'], 4096))
        except (FileNotFoundError, PublicationPending):
            return None
        expected = {'attempt': stem(req), 'nonce': req['sync']['nonce'], 'state': state}
        if ready != expected:
            raise ValueError('synchronization ready envelope mismatch')
        fact = observe(ready)
        if not isinstance(fact, dict) or not fact:
            raise ValueError('no real external observation for synchronization')
        release = {**expected, 'state': 'release'}
        if req['attack'] == 'NB-21':
            qid = fact.get('question', {}).get('qid')
            if type(qid) is not int or not 1 <= qid < 2**64:
                raise ValueError('NB-21 release needs a witnessed question ID')
            release['question'] = qid
        publish(with_files, req['sync']['release'], json_bytes(release))
    finally:
        with_files.close()
    return fact


class CollectionError(ValueError):
    """Quality failure with only envelope-checked observation/verified captures."""
    def __init__(self, cause, observation, captures):
        super().__init__(type(cause).__name__ + ': ' + str(cause)[:512])
        self.observation, self.captures = observation, dict(captures)


def collect(work, req, evidence):
    record, observation, captures = None, None, {}
    archived = {'attempt': stem(req), 'captures': {}}
    try:
        request_data = read_beneath(work, REQUEST, 65536)
        archived['request'] = evidence.raw(request_data, suffix='request.json')
        if decode(request_data) != req:
            raise ValueError('runner request was missing or changed')
        data = read_beneath(work, stem(req) + '-observed.json', 65536)
        # Preserve even malformed/incomplete records before interpreting them.
        archived['observation'] = evidence.raw(data, suffix='observed.json')
        record = decode(data)
        if (not isinstance(record, dict) or record.get('v') != 1
                or record.get('attempt') != stem(req)
                or type(record.get('complete')) is not bool
                or type(record.get('control_ok')) is not bool):
            raise ValueError('invalid runner observation envelope')
        observation = record
        items = record.get('captures', [])
        if not isinstance(items, list) or len(items) > 64:
            raise ValueError('invalid capture list')
        seen, total = set(), 0
        for item in items:
            if not isinstance(item, dict):
                raise ValueError('invalid capture receipt')
            name, phase = item.get('path'), item.get('phase')
            if (not isinstance(name, str) or phase not in ('control', 'action')
                    or '/' in name or '\\' in name or name in seen
                    or not name.startswith(stem(req) + '-' + phase + '-')
                    or not name.endswith('.capture') or type(item.get('bytes')) is not int):
                raise ValueError('capture identity/phase mismatch')
            seen.add(name)
            raw = read_beneath(work, name, 2 * 1024 * 1024 - total)
            total += len(raw)
            if item['bytes'] != len(raw) or item.get('sha256') != hashlib.sha256(raw).hexdigest():
                raise ValueError('capture digest/size mismatch')
            archived['captures'][name] = evidence.raw(raw, suffix='capture')
            captures[name] = raw
        if record['complete'] is not True or record.get('error') is not None:
            raise ValueError('incomplete runner observation: ' + str(record.get('error'))[:512])
        return record, captures
    except (ValueError, OSError, TypeError, KeyError) as exc:
        raise CollectionError(exc, observation, captures) from exc
    finally:
        # This maps workspace names to controller-owned files, including failures.
        if len(archived) > 2:
            evidence.raw(json_bytes(archived), suffix='collection.json')
