"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Observed mechanism from the engine's own diagnostics (tests.md 1.4: external facts
# first, then request observation, E-09 and connector diagnostics). The name is derived
# from what the attempt's E-09 decision and connector log say happened to the action
# request; it is never copied from the expectation. No unique reading -> None.
import json

CREDENTIAL_REFUSED = 9  # engine deny_reason: credential header and no usable credential record
# The connector's whole log line for a canonical Host refusal (connector/session.py wraps
# canonical.py's Malformed): clause 3's forbidden-name check, shared with clause 1.
HOST_REJECTED = 'request does not read: forbidden header host (条款 3)'
# Other refusals of a whole request before admission; any of them makes the Host reading ambiguous.
PRE_ADMISSION = ('request does not read:', 'IP literal refused')
REFUSAL_EVENTS = ('request_refused', 'connection_error')


def records(e09):
    """The attempt slice as parsed JSONL objects (cb_outlets verified its framing)."""
    return [json.loads(line) for line in e09.splitlines() if line.strip()]


def connector_records(logs):
    found = []
    for line in logs.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            found.append(item)
    return found


def connector_reasons(logs):
    return [r['reason'] for r in connector_records(logs) if isinstance(r.get('reason'), str)]


def host_rejected(logs, items, parameters):
    """CB-12 before admission: this row's connector logged exactly one connection_closed with the
    Host refusal and no other whole-request refusal, while the same row's control request was
    admitted (so the E-09 slice is this row's). Each send is its own connection and only the
    action carries a host header, so the one record is the action's."""
    log = connector_records(logs)
    closed = [r for r in log if r.get('event') == 'connection_closed' and isinstance(r.get('reason'), str)]
    host = [r for r in closed if r['reason'] == HOST_REJECTED]
    other = [r for r in closed if r['reason'] != HOST_REJECTED and r['reason'].startswith(PRE_ADMISSION)]
    other += [r for r in log if r.get('event') in REFUSAL_EVENTS]
    control = decisions(items, parameters.get('control_path', ''))
    return len(host) == 1 and not other and bool(control)


def decisions(items, path):
    """(admission detail, decision record) for each admitted request on the action path."""
    admitted = [r['detail'] for r in items if r.get('kind') == 'request_admitted' and isinstance(r.get('detail'), dict)]
    decided = {(r['detail'].get('seq'), r['detail'].get('admission')): r for r in items
               if r.get('kind') == 'request_decided' and isinstance(r.get('detail'), dict)}
    return [(a, decided.get((a.get('seq'), a.get('admission')))) for a in admitted
            if str(a.get('path', '')).split('?')[0] == path]


def summary(pairs, reasons):
    return {'admissions': [{k: a.get(k) for k in ('method', 'scheme', 'host', 'port', 'header_names')} for a, _ in pairs],
            'decisions': [None if d is None else {'outcome': d.get('outcome'), 'reason_code': d.get('reason_code'),
                          **{k: d['detail'].get(k) for k in ('credential', 'account', 'deny_reason', 'account_destination')
                             if k in d['detail']}} for _, d in pairs],
            'connector_reasons': reasons[:16]}


def observe(spec, parameters, accounts, requests, diagnostics):
    """Returns (mechanism or None, diagnostic summary). Engine configuration only."""
    if not diagnostics:
        return None, {'missing': 'no engine diagnostics'}
    items, reasons = records(diagnostics['e09']), connector_reasons(diagnostics['connector'])
    pairs = decisions(items, parameters['path'])
    facts = summary(pairs, reasons)
    source = accounts[spec['source']]
    if not pairs:
        # Rejected before admission: only the connector's canonical check explains it.
        named = host_rejected(diagnostics['connector'], items, parameters)
        return ('canonical-host-rejection' if named else None), facts
    if len(pairs) != 1 or pairs[0][1] is None:
        return None, facts
    admission, decision = pairs[0]
    detail = decision['detail']
    names = admission.get('header_names') or []
    if decision.get('outcome') == 'deny':
        refused = decision.get('reason_code') == 'credential_refused' and detail.get('deny_reason') == CREDENTIAL_REFUSED
        return ('row-account-selection' if refused else None), facts
    if decision.get('outcome') != 'allow':
        return None, facts
    placed, account = detail.get('credential'), detail.get('account')
    if placed == 'placed':
        if account != source.account:
            # The core placed the row's own account, not the one whose placeholder was sent.
            return ('row-account-selection' if account in {a.account for a in accounts.values()} else None), facts
        other = 'authorization' if source.header == 'x-api-key' else 'x-api-key'
        if source.header in names and other in names:
            return 'registered-placement-only', facts
        sink = [r for r in requests if r['path'].startswith('/nb-decoy-cb/collect/')
                and r['path'].endswith('/' + parameters['path'].split('/')[-1])]
        if spec['mode'] in ('302', '307', '308') and not sink:
            return 'no-redirect-follow', facts
        return None, facts
    if placed != 'none':
        return None, facts
    if admission.get('scheme') == 'http' and admission.get('port') == 80 and source.header in names:
        return 'https-release-only', facts
    if source.header not in names and detail.get('account_destination') is True:
        return 'registered-placement-only', facts
    if source.header not in names and detail.get('account_destination') is False:
        return 'truth-outside-agent', facts
    return None, facts


def placed_for(diagnostics, path):
    """PC-CREDENTIAL: (credential, account) the core decided for each admitted request on path."""
    pairs = decisions(records(diagnostics['e09']), path) if diagnostics else []
    return [(d or {}).get('detail', {}).get('credential') for _, d in pairs], \
           [(d or {}).get('detail', {}).get('account') for _, d in pairs]
