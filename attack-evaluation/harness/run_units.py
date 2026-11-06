"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
from dataclasses import dataclass
from pathlib import Path
from common import PURPOSE

BASE = Path('Thesis/Work/Submission/attack_evaluation')
CB_PURPOSE = '这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。'

@dataclass(frozen=True)
class Unit:
    name: str
    purpose: str
    @property
    def root(self): return BASE / self.name
    @property
    def runs(self): return self.root / 'runs'
    @property
    def spec(self): return self.root / 'tests.md'
    def script(self, key, name):
        if Path(name).name != name or not name.endswith('.py'):
            raise ValueError('explicit flat module required')
        # Original controls/support are deliberately reused, not copied or scanned.
        shared = {'SUP-VICTIM','SUP-AUXILIARY'}
        owner = 'no-bypass' if self.name == 'credential-binding' and key in shared else self.name
        return BASE / owner / 'scripts' / name

UNITS = {'no-bypass': Unit('no-bypass', PURPOSE),
         'credential-binding': Unit('credential-binding', CB_PURPOSE)}

def unit(name='no-bypass'):
    if name not in UNITS: raise ValueError('unknown evaluation unit')
    return UNITS[name]

def cases_for(name, legacy, targets=()):
    selected = unit(name)
    if selected.name == 'no-bypass':
        if targets:raise ValueError('target subsets are credential-binding only')
        return legacy
    from cb_registry import registry
    return registry(targets)

def report_purpose(header=None):
    return unit((header or {}).get('unit', 'no-bypass')).purpose
