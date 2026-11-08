"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
import base64
import json
from common import identity
from cb_sentinels import hits

OUTLETS = ('upstream', 'responses', 'trace', 'e09', 'core-connector-output', 'environ', 'core-dump')
MAX_BYTES = 2 * 1024 * 1024


class Pairs(list):
    """A JSON object as its (key, value) pairs: duplicate keys and keys themselves stay scannable."""


def _records(data):
    """The whole input as one JSON document (multi-line JSON included), else each line as JSONL."""
    try: return [json.loads(data, object_pairs_hook=Pairs)]
    except (ValueError, UnicodeDecodeError): pass
    found = []
    for line in data.splitlines():
        try: found.append(json.loads(line, object_pairs_hook=Pairs))
        except (ValueError, UnicodeDecodeError): continue
    return found


def scan_bytes(data, accounts):
    """Raw first, then bounded JSON string/key/base64 wrappers; no arbitrary-code decoding."""
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('scan input missing or exceeds byte budget')
    findings = [{**h, 'encoding': 'raw'} for h in hits(data, accounts)]
    # Depth/node bounds are per JSON record; the decoded byte budget spans the input.
    budget, nodes = len(data), 0
    def text(value, path, encoding):
        nonlocal budget
        raw = value.encode('utf-8', 'surrogatepass')
        budget += len(raw)
        if budget > 4 * MAX_BYTES: raise ValueError('decoded scan byte budget')
        findings.extend({**h, 'encoding': encoding, 'path': path} for h in hits(raw, accounts))
        return raw
    def walk(value, path, depth):
        nonlocal budget, nodes
        nodes += 1
        if depth > 16 or nodes > 8192: raise ValueError('scan JSON depth/node bound')
        if isinstance(value, Pairs):
            for key, child in value:
                text(key, path + '/' + key, 'json-key')
                walk(child, path + '/' + key, depth + 1)
        elif isinstance(value, list):
            for i, child in enumerate(value): walk(child, path + '/' + str(i), depth + 1)
        elif isinstance(value, str):
            raw = text(value, path, 'json-string')
            # Known wrapper fields only; a normal string that merely resembles base64 is not an extra encoding claim.
            if path.endswith(('_base64', '/base64', '/data_b64')):
                decoded = base64.b64decode(raw, validate=True)
                budget += len(decoded)
                if budget > 4 * MAX_BYTES: raise ValueError('decoded scan byte budget')
                findings.extend({**h, 'encoding': 'base64', 'path': path} for h in hits(decoded, accounts))
    for value in _records(data):
        nodes = 0
        walk(value, '', 0)
    return {'identity': identity(data), 'hits': findings}


def request_scan(receipt, accounts, release=None):
    """The trusted service must archive raw wire components; legal release is ONE exact header value.
    Never exempt a host, an entire request, a body, or another account's value.
    release is controller-owned and binds this exact nonce/path, destination, account and row.
    """
    raw_head = base64.b64decode(receipt['head_base64'], validate=True)
    body = base64.b64decode(receipt['payload_base64'], validate=True)
    lines = raw_head.split(b'\r\n')
    if not lines or len(raw_head) > 16384 or len(body) != receipt['bytes']:
        raise ValueError('upstream raw head/body incomplete')
    method, target, version = lines[0].decode('ascii').split(' ')
    pairs = []
    for line in lines[1:]:
        name, value = line.split(b':',1)
        pairs.append((name.decode('ascii').lower(),value.strip()))
    if method != receipt['method'] or target != receipt['path'] or version != 'HTTP/1.1':
        raise ValueError('parsed receipt differs from raw request line')
    hosts = [v.decode('ascii').split(':')[0] for k,v in pairs if k == 'host']
    if hosts != [receipt['host']]: raise ValueError('receipt Host differs from raw bytes')
    hits_out, allowed = [], []
    # The body gets the same raw-then-JSON decoding as every other outlet (tests.md 1.3).
    for label, data in [('request-line',lines[0]),('body',body)]:
        hits_out += [{**h,'field':label} for h in scan_bytes(data,accounts)['hits']]
    for i,(name,value) in enumerate(pairs):
        hits_out += [{**h,'field':'header-name','index':i} for h in hits(name.encode(),accounts)]
        for h in hits(value, accounts):
            a = next(a for a in accounts if a.account == h['account'])
            legal = bool(release and release.get('account') == a.account
                and release.get('row') and release.get('entry') and release.get('nonce')
                and receipt['method'] == release.get('method')
                and receipt['path'] == release.get('path')
                and release.get('nonce') in receipt['path']
                and receipt.get('scheme') == 'https' and receipt.get('port') == a.port
                and receipt['host'] == a.host and receipt.get('sni') == a.host
                and name == a.header and value == a.value
                and sum(k == name for k,_ in pairs) == 1)
            item = {**h,'field':name,'index':i}
            (allowed if legal else hits_out).append(item)
    return {'raw_head':identity(raw_head),'body':identity(body),'forbidden':hits_out,'allowed':allowed}


class Scan:
    """Per-attempt inventory. Absent/unreadable is never a negative scan."""
    def __init__(self, accounts):
        self.accounts, self.items = tuple(accounts), []
        forms=[a.truth for a in accounts]
        if not forms or len(set(forms)) != len(forms): raise ValueError('independent sentinels required')

    def add(self, outlet, source, data, *, complete, provenance, preset=False):
        if outlet not in OUTLETS or not source or not provenance:
            raise ValueError('declared outlet with source/provenance required')
        if type(complete) is not bool: raise ValueError('explicit coverage required')
        if preset and (outlet != 'environ' or provenance.get('role') != 'undefended-parent'
                       or provenance.get('stage') != 'initial'):
            raise ValueError('only initial undefended parent environment is a preset exception')
        result = scan_bytes(data,self.accounts)
        item = {'outlet':outlet,'source':source,'complete':complete,
                'provenance':provenance,'preset':preset, **result}
        self.items.append(item)
        return item

    def unavailable(self, outlet, source, reason, witness=None):
        if outlet not in OUTLETS or not reason: raise ValueError('missing coverage needs reason')
        item = {'outlet':outlet,'source':source,'complete':False,'reason':reason,'hits':[]}
        if witness is not None: item['witness'] = witness
        self.items.append(item)

    def not_produced(self, outlet, source, witness):
        if outlet != 'core-dump' or not witness: raise ValueError('no-dump needs external witness')
        self.items.append({'outlet':outlet,'source':source,'complete':True,
                           'state':'not-produced','witness':witness,'hits':[]})

    def result(self):
        present={x['outlet'] for x in self.items}
        gaps=[o+':missing' for o in OUTLETS if o not in present]
        gaps += [x['outlet']+':'+x.get('reason','incomplete') for x in self.items if not x['complete']]
        forbidden=[{'source':x['source'],'outlet':x['outlet'],**h} for x in self.items
                   if not x.get('preset') for h in x.get('hits',[])]
        return {'complete':not gaps,'gaps':gaps,'forbidden':forbidden,'items':self.items}
