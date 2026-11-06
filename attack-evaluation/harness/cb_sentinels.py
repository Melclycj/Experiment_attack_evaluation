"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import secrets
from dataclasses import dataclass
from common import identity

PLACEMENTS = ('api-key', 'bearer', 'token', 'basic')

@dataclass(frozen=True)
class Credential:
    account: str
    host: str
    port: int
    placement: str
    truth: bytes
    password: bytes = b''

    @property
    def header(self): return 'x-api-key' if self.placement == 'api-key' else 'authorization'

    @property
    def value(self):
        if self.placement == 'api-key': return self.truth
        if self.placement == 'basic':
            return b'Basic ' + base64.b64encode(self.truth + b':' + self.password)
        return (b'Bearer' if self.placement == 'bearer' else b'token') + b' ' + self.truth

    def forms(self):
        result = {'truth': self.truth, 'header': self.value}
        if self.placement == 'basic':
            plain = self.truth + b':' + self.password
            result.update(password=self.password, pair=plain, base64=base64.b64encode(plain))
        return result

    def metadata(self):
        return {'account': self.account, 'host': self.host, 'port': self.port,
                'placement': self.placement, 'header': self.header,
                'forms': {k: identity(v) for k, v in self.forms().items()}}


def new_credential(account, host, port, placement):
    if placement not in PLACEMENTS or port not in (80,443,8443):  # 8443: CB-14 条款 8 keep endpoint
        raise ValueError('unknown credential placement/port')
    if not account.startswith('nb-decoy-') or not host.startswith('nb-decoy-') or not host.endswith('.test'):
        raise ValueError('only synthetic decoy accounts/hosts')
    def fresh(): return ('nb-decoy-secret-' + secrets.token_hex(24)).encode()
    return Credential(account, host, port, placement, fresh(), fresh() if placement == 'basic' else b'')


def hits(data, accounts):
    if not isinstance(data, bytes): raise TypeError('scan raw bytes first')
    found = []
    for a in accounts:
        for label, value in a.forms().items():
            offset = data.find(value)
            if offset >= 0:
                found.append({'account': a.account, 'form': label, 'offset': offset,
                              'length': len(value)})
    return found
