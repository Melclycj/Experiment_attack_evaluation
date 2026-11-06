"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
from dataclasses import dataclass, field
from copy import deepcopy
from pathlib import Path
import re

@dataclass(frozen=True)
class Case:
    """Explicit reviewed step-4 entry; host adapter is trusted controller code.

    factory(runtime) -> adapter with contract(), prepare(config, repeat, contract),
    synchronize(prepared, ready), interact(handle, prepared), observe(prepared,
    observation, captures, window), restore(prepared). Contract has attack,
    targets (stable logical IDs), construction, operations; no nonce/config.
    Optional targets_by_config declares both arms' exact target lists; only the
    historical NB-23 undefended victim-connector omission is readable. New
    NB-23 contracts require all four targets in both arms. This never
    exempts a blocked engine target from its own undefended prerequisite.
    prepare returns targets, parameters, before. observe returns classify_target
    keyword arguments per logical target, plus prerequisite_ok for undefended.
    """
    attack: str
    module: str
    factory: object
    expected: dict
    repeats: int = 1
    kind: str = 'attack'
    sync: str | None = None
    branches: tuple = ()  # NB-15 alias writes: separate closed rows, one R/deadline

    expected_by_config: dict = field(default_factory=dict)

    def expectation(self, config):
        """Config expectations are metadata, not an outcome override.
        Current file attacks expect undefended success. Future exceptions (e.g.
        NB-23) must register their own expectation, not inherit engine mechanisms.
        """
        if config in self.expected_by_config:
            return deepcopy(self.expected_by_config[config])
        if config == 'engine' or (config == 'undefended' and self.kind in ('control', 'boundary')):
            return deepcopy(self.expected)
        if config == 'undefended':
            return {'outcome': 'succeeded'}
        raise ValueError('configuration has no registered expectation')

    def validate(self):
        if not re.fullmatch(r'NB-(?:0[1-9]|1[0-9]|2[0-8])|CB-(?:0[1-9]|1[0-2]|14)|PC-[A-Z0-9-]+|BD-[A-Z0-9-]+', self.attack):
            raise ValueError('unknown case ID')
        if (Path(self.module).name != self.module or not self.module.endswith('.py')
                or not callable(self.factory) or not self.expected
                or type(self.repeats) is not int or not 1 <= self.repeats <= 128
                or self.kind not in ('attack', 'control', 'boundary') or self.sync not in (None, 'sent', 'done')):
            raise ValueError('invalid explicit case registration')
        # ID prefix fixes the kind: PC- is a positive control, BD- a boundary demonstration, NB- an attack.
        prefix_kind = {'PC-': 'control', 'BD-': 'boundary'}
        expected_kind = next((k for p, k in prefix_kind.items() if self.attack.startswith(p)), 'attack')
        if self.kind != expected_kind:
            raise ValueError('case kind disagrees with ID')
        if self.branches:
            if self.attack.startswith('CB-') or self.attack=='PC-CREDENTIAL':
                from cell.cb_spec import BRANCHES
                allowed=BRANCHES[self.attack]
                if self.sync!='sent' or tuple(b for b in allowed if b in self.branches)!=self.branches:
                    raise ValueError('credential target subset differs from frozen specification')
            elif self.attack != 'NB-15' or self.branches != ('source','mount') or self.sync:
                raise ValueError('only NB-15 owns closed per-path branch rows')
        return self

# Explicit 4a controls, 4b files and 4c connections. Other NB IDs fail selection.
from positive_controls import WorkspaceControl, ProxyControl, DialogueControl
from support_rows import SupportRows
from functools import partial
from file_cases import FileCase
from cell.nb_file_spec import KINDS

CASES = {cls.attack: Case(cls.attack, cls.attack + '.py', cls,
                         {'outcome': 'succeeded'}, kind='control')
         for cls in (WorkspaceControl, ProxyControl, DialogueControl)}
# Boundary demonstrations (engine-only, expected succeeded): the policy layer is delegated to the PDP, so content to
# an allowed destination passes under the trivial PDP. agent-rm-model 648d60f2 4.2, 4.3; METHOD rule 10.
from boundary_demo import ExfilDemo, OwnKeyDemo
CASES.update({cls.attack: Case(cls.attack, cls.attack + '.py', cls,
                              {'outcome': 'succeeded'}, kind='boundary') for cls in (ExfilDemo, OwnKeyDemo)})
CASES.update({attack: Case(attack, attack + '.py', partial(FileCase, attack=attack),
    {'outcome': 'blocked', 'mechanism': 'file-view', 'location': 'native/sandbox/child.c:pivot_root'},
    branches=('source', 'mount') if attack == 'NB-15' else ()) for attack in KINDS})
from connection_cases import ConnectionCase
from cell.nb_conn_spec import SPECS

CASES.update({attack: Case(attack, attack + '.py', partial(ConnectionCase, attack=attack),
    {'outcome': 'blocked',
     'mechanism': 'file-view + net-namespace' if attack in ('NB-19', 'NB-27') else 'net-namespace',
     'location': ('native/sandbox/spawner.c:clone_ready(CLONE_NEWNET)'
                  + ('; native/sandbox/child.c:w2_child_launch(pivot_root)'
                     if attack in ('NB-19', 'NB-27') else ''))}) for attack in SPECS})
from engine_cases import EngineCase
from cell.nb_engine_spec import SPECS as ENGINE_OBJECTS

CASES.update({attack: Case(attack, attack + '.py', partial(EngineCase, attack=attack),
    {'outcome': 'blocked', 'mechanism': 'pid-namespace' if attack == 'NB-23' else 'file-view',
     'location': ('native/sandbox/spawner.c:clone_ready(CLONE_NEWPID)' if attack == 'NB-23'
                  else 'native/sandbox/child.c:w2_child_launch(pivot_root)')},
    sync='sent' if attack == 'NB-21' else None,
    expected_by_config={'undefended': {'outcome':'succeeded', 'targets':{
        'core':'stopped', 'spawner':'identity-matched EPERM',
        'auxiliary':'identity-matched EPERM', 'victim':'identity-matched EPERM',
        'auxiliary-worker':'identity-matched EPERM', 'victim-worker':'identity-matched EPERM'}}}
        if attack=='NB-23' else {})
    for attack in ENGINE_OBJECTS})
from fd_case import FdCase
from userns_case import UsernsCase

CASES['NB-24'] = Case('NB-24', 'NB-24.py', FdCase,
    {'outcome': 'blocked', 'mechanism': 'file-view',
     'location': 'native/sandbox/child.c:w2_child_launch(pivot_root)'})
CASES['NB-26'] = Case('NB-26', 'NB-26.py', UsernsCase,
    {'outcome': 'blocked', 'mechanism': 'seccomp + no-cap-net-admin',
     'location': 'native/sandbox/policy.c + child.c:capability-drop'}, sync='done')
SUPPORT = SupportRows
SUPPORT_MODULES = {'SUP-VICTIM': 'SUP-VICTIM.py', 'SUP-AUXILIARY': 'SUP-AUXILIARY.py'}
