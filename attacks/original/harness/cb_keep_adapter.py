"""这是 2.3 凭据使用绑定的验证测试：CB-14 条款 8 的 host 适配器。只对本次运行自建的账户、哨兵与断网上游，
检查上游连接是否按账户分开（第二帧不复用第一帧为账户 A 建立的连接）；不使用真实凭据。

与 CredentialCase（CB-01–12）分开的一条独立路径：复用成熟的 Accounts/WorkspaceFiles，但只建一个保持连接端点
（keep host:8443，唯一账户 A、起行指定 A），两帧由 cell 侧 keep_action 发出，判官是 cb_keep_judge。targets 置空：
keep 上游在 8443、不是 cb_service 的监听，其存活由 CredentialUpstream.start 的 keep-ready 确认，不经 rt.targets。"""
import json
import secrets
from cb_accounts import Accounts, host_port
from cb_case_plan import plan, paths
from cb_profile import HOSTS, ROOT
from cell.cb_spec import BRANCHES
from case_io import WorkspaceFiles
from common import identity, json_bytes
from safeio import read_beneath


class KeepCase:
    """Accounts, releases and expectations never come from the cell."""
    def __init__(self, runtime, attack, branches=None):
        self.rt, self.attack = runtime, attack
        self.branches = tuple(branches or BRANCHES[attack])
        self.accounts = None
        self.files = None
        self.current = None

    def contract(self):
        return {'attack': self.attack, 'targets': list(self.branches),
                'construction': {key: plan(self.attack, key) for key in self.branches},
                'operations': ['declare-accounts', 'reference-rows', 'keep-two-frame', 'scan-all-outlets', 'restore'],
                'baseline': 'engine-placeholder / undefended-preseeded-synthetic-truth'}

    def prepare_branch(self, config, repeat, contract, branch):
        if config not in ('engine', 'undefended') or contract != self.contract():
            raise ValueError('credential contract/config changed')
        if self.accounts is not None:
            raise ValueError('previous credential target not restored')
        spec = plan(self.attack, branch)
        rt = self.rt
        self.accounts = Accounts(rt.deployment)
        values = self.accounts.create(HOSTS[spec['placement']], spec['port'], spec['placement'])
        rt.own(values.values(), self.attack, config, branch)
        self.current = {'spec': spec, 'accounts': values, 'config': config, 'branch': branch,
                        'entries': [], 'references': []}
        for credential in values.values():
            self.accounts.register(credential)
        self.current['reference_accounts'] = values
        self.current['metadata'] = list(self.accounts.receipts)
        self.current['all_accounts'] = list(self.accounts.credentials)
        # Sink entries carry the non-secret control marker; the keep entry is the exact 8443 endpoint with account A.
        self.entry('work0', HOSTS['sink'], 443, ())
        self.entry('work1', HOSTS['sink'], 443, ())
        self.entry('work0', spec['host'], spec['port'], [values[x].account for x in spec['accounts']])
        rt.row_accounts = {'work0': [(host_port(spec['host'], spec['port']), values[spec['selected']].account)]}
        self.files = WorkspaceFiles(rt, 'work0')
        nonce = secrets.token_hex(24)
        marker = 'nb-decoy-marker-' + secrets.token_hex(24)
        placeholder = 'nb-decoy-placeholder-' + secrets.token_hex(24)
        p = {**paths(spec, nonce), 'host': spec['host'], 'port': spec['port'], 'scheme': spec['scheme'],
             'header': values[spec['source']].header, 'branch_mode': spec['mode'], 'marker': marker,
             'placeholder': placeholder, 'ca': str(rt.deployment.root / 'tls/ca.pem'),
             'config_path': 'nb-decoy-cb-input-' + nonce, 'config': config}
        value = values[spec['source']].value.decode() if config == 'undefended' else placeholder
        before = self.files.write(p['config_path'], json_bytes({'credential': value, 'marker': marker}))
        rt.undefended_environment = {}  # the keep two-frame action spawns no child; env is unused
        # One abstract decoy target to satisfy the cell's validate_request (1..64 targets); the keep two-frame action
        # uses p['host']/p['port'], not ctx.target, and the keep upstream's liveness is confirmed at deploy (keep-ready),
        # so no inet listener is pinned here (keep_attempt skips rt.targets.verify).
        self.current.update(targets={branch: {'kind': 'abstract', 'name': 'nb-decoy-keep'}}, parameters=p,
                            before={'config': before, 'accounts': self.current['metadata'], 'spec': spec})
        return self.current

    def entry(self, workspace, host, port, accounts):
        result = self.accounts.set_entry(workspace, host, port, accounts, (ROOT,))
        key = (workspace, host, port)
        if key not in self.current['entries']:
            self.current['entries'].append(key)
        mirror = read_beneath(self.rt.deployment.root, 'state/workspaces/' + workspace + '.json')
        receipt = {'workspace': workspace, 'host': host, 'port': port, 'accounts': list(accounts),
                   'reply': result, 'mirror': json.loads(mirror), 'mirror_identity': identity(mirror)}
        self.current.setdefault('entry_receipts', []).append(receipt)
        return receipt

    def synchronize(self, prepared, ready):
        return {'handshake': ready, 'action': 'continue-frozen-request'}

    def restore(self, prepared):
        if any(not r.closed for r in self.rt.rows):
            raise ValueError('cannot restore credential material while a row is live')
        errors = []
        if self.files:
            try:
                self.files.restore()
            except Exception as exc:
                errors.append(str(exc))
        for workspace, host, port in reversed(prepared.get('entries', [])):
            try:
                self.rt.deployment.admin.call('entry', 'del', workspace, 'exact', host_port(host, port))
            except Exception as exc:
                errors.append(str(exc))
        if self.accounts:
            try:
                self.accounts.close()
            except Exception as exc:
                errors.append(str(exc))
        self.rt.undefended_environment = {}
        self.rt.row_accounts = {}
        if errors:
            raise RuntimeError('credential restore failed: ' + '; '.join(errors))
        self.accounts = self.files = self.current = None

    def dispose(self):
        if self.files:
            self.files.close()
