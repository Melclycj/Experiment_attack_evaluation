"""mitmproxy addon for the host measurement of the workload seccomp allowlist (build plan 7.4 step 3;
allowlist-derivation.md "怎样跑"). Measurement only, never part of the engine.

It stands in for the connector on the host: the agents hold only the placeholders they hold in the cell, and this
addon puts the real value in their place on the way out (x-api-key, Authorization Bearer or token, the Basic password
position), so that the requests succeed and the code paths after them run and are measured. Every request is logged
with the operation the runner is measuring (read from a label file at request time) in the shape gate_items.py's
judges read, so the gate items are judged on the host by the same functions as in the cell.

Environment: W2_DERIVE_SUBS (JSON file {placement: {placeholder: {"truth": ..., "account": ...}}}, placements
x-api-key, bearer, basic_password), W2_DERIVE_LOG (JSONL output), W2_DERIVE_LABEL (file holding the current label).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import time
from typing import Any

from mitmproxy import http

with open(os.environ['W2_DERIVE_SUBS'], encoding='utf-8') as _f:
    SUBS: dict[str, dict[str, dict[str, str]]] = json.load(_f)
LOG = os.environ['W2_DERIVE_LOG']
LABEL = os.environ['W2_DERIVE_LABEL']


def _label() -> str:
    try:
        with open(LABEL, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def _substitute(headers: http.Headers) -> tuple[str, str | None]:
    """Replace one placeholder in its placement; returns (credential, account) as the gate's trace records them."""
    key = headers.get('x-api-key')
    if key in SUBS['x-api-key']:
        headers['x-api-key'] = SUBS['x-api-key'][key]['truth']
        return 'placed', SUBS['x-api-key'][key]['account']
    scheme, _, rest = (headers.get('authorization') or '').partition(' ')
    if scheme.lower() in ('bearer', 'token') and rest in SUBS['bearer']:
        headers['authorization'] = f"{scheme} {SUBS['bearer'][rest]['truth']}"
        return 'placed', SUBS['bearer'][rest]['account']
    if scheme.lower() == 'basic':
        try:
            user, _, password = base64.b64decode(rest, validate=True).decode('latin-1').partition(':')
        except (binascii.Error, ValueError):
            return 'none', None
        if password in SUBS['basic_password']:
            sub = SUBS['basic_password'][password]
            pair = base64.b64encode(f"{user}:{sub['truth']}".encode('latin-1')).decode('ascii')
            headers['authorization'] = f'Basic {pair}'
            return 'placed', sub['account']
    return 'none', None


class Substitute:
    # requestheaders, not request: with stream_large_bodies the request event fires only after a body has been streamed
    # upstream, its headers already sent (a POST went out with the placeholder in the first smoke run, 401)
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        names = sorted({k.lower() for k in flow.request.headers.keys()})
        credential, account = _substitute(flow.request.headers)
        flow.metadata['w2'] = {'t': time.time(), 'op': _label(), 'credential': credential, 'account': account,
                               'header_names': names}

    def response(self, flow: http.HTTPFlow) -> None:
        self._log(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        self._log(flow)

    def _log(self, flow: http.HTTPFlow) -> None:
        meta: dict[str, Any] = flow.metadata.get('w2', {})
        status = flow.response.status_code if flow.response is not None else None
        record = {'t': meta.get('t'), 'op': meta.get('op'), 'method': flow.request.method,
                  'host': flow.request.pretty_host, 'port': flow.request.port,
                  'path': flow.request.path.split('?', 1)[0], 'header_names': meta.get('header_names', []),
                  'decision': 'allow', 'credential': meta.get('credential', 'none'), 'account': meta.get('account'),
                  'status': status, 'result': None if flow.error is not None else 1,
                  'error': type(flow.error).__name__ if flow.error is not None else None}
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')


addons = [Substitute()]
