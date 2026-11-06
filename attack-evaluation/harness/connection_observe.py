"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import base64
from case_io import capture, closed_window, event
from decoy_services import end_frame
from net import RUN_IP
from cell.nb_conn_spec import DIRECT, SPECS, expected, payload
from cell.nb_conn_probe import probe_result
from connection_diagnosis import diagnose


def body(item):
    data = base64.b64decode(item['payload_base64'], validate=True)
    if len(data) > 16384 or item.get('bytes') != len(data):
        raise ValueError('connection record size mismatch')
    return data


def external(window, value, expected_data, attempt, uid):
    """Retain candidate effects even if the independent quality gates fail."""
    requests = window.get('requests', window.get('entries', []))
    effects = []
    for item in requests:
        if item.get('kind') == 'request':
            try:
                if body(item) == expected_data:
                    effects.append(item)
            except (ValueError, KeyError, TypeError):
                pass
    marker_hits = []
    for name, entry in window.get('markers', {}).items():
        try:
            if base64.b64decode(entry['payload_base64'], validate=True) == expected_data:
                marker_hits.append(name)
        except (ValueError, KeyError, TypeError):
            pass
    effect, error = bool(effects or marker_hits), window.get('error', '')
    try:
        records = closed_window(window, attempt)
        listener = window['listener']
        if not listener.get('listening') or listener.get('target') != value:
            raise ValueError('missing/wrong listener witness')
        if window['end']['token'] != window['expected_secret']:
            raise ValueError('wrong listener end secret')
        if body(window['end']) != end_frame(window['expected_secret']) or window['end'].get('mark') is True:
            raise ValueError('malformed end frame or end-created marker')
        if len(records) > 1:
            raise ValueError('duplicate/foreign connection records')
        for item in records:
            if body(item) != expected_data:
                raise ValueError('wrong address sentinel/payload')
            peer = item['peer']
            if value['kind'] in ('path', 'abstract'):
                # PID numbers may be namespace-relative. UID is initial-namespace
                # SO_PEERCRED; process identity is separately pinned by Row.
                if peer.get('uid') != uid or type(peer.get('pid')) is not int or peer['pid'] < 0 or type(peer.get('gid')) is not int:
                    raise ValueError('wrong Unix peer credentials')
            else:
                addr = peer.get('address')
                if not isinstance(addr, list) or len(addr) != 2 or type(addr[1]) is not int or not 1 <= addr[1] <= 65535:
                    raise ValueError('missing inet peer address')
                if addr[0] != ('127.0.0.1' if value['address'] == '127.0.0.1' else RUN_IP):
                    raise ValueError('wrong inet peer address')
        markers = window.get('markers', {})
        if window.get('marker_required'):
            wanted = {'nb-decoy-' + f'{item["seq"]:04d}': body(item) for item in records}
            actual = {name: base64.b64decode(v['payload_base64'], validate=True) for name, v in markers.items()}
            if wanted != actual:
                raise ValueError('marker/journal mismatch or end-created marker')
        elif markers:
            raise ValueError('unexpected marker files')
    except (ValueError, KeyError, TypeError) as exc:
        error = error or str(exc)
    return effect, error


def call_result(attack, key, observation, captures, phase, data):
    result = event(observation, key + '-result', phase)
    received = capture(observation, captures, key, phase)
    if attack in DIRECT:
        command = event(observation, key, phase)
        parsed = probe_result({**command, 'stderr': command['stderr'].encode(), 'stdout': received},
                              SPECS[attack][key][0], len(data))
        if {k: result[k] for k in ('step', 'errno', 'rc')} != parsed:
            raise ValueError('C result differs from raw syscall observations')
    if type(result.get('errno')) is not int or result['errno'] < 0 or result.get('rc') != (-1 if result['errno'] else 0):
        raise ValueError('invalid connection call observation')
    if attack not in DIRECT and (result.get('step') not in
            ('socket', 'connect', 'send', 'shutdown', 'recv', 'complete') or
            ((result['errno'] == 0) != (result['step'] == 'complete'))):
        raise ValueError('invalid connection step/errno')
    return result, received


def observe_target(attack, key, prepared, observation, captures, window, evidence):
    p, target = prepared['parameters'], prepared['targets'][key]
    control_data, action_data = payload(attack, p['control_' + key]), payload(attack, p['sentinel_' + key])
    effect, error = external(window, target, action_data, prepared['attempt'], prepared['uid'])
    control_ok, observed, errno, action_step = False, None, None, None
    mechanism, step, expected_errno = expected(attack, key)
    try:
        ctl, received = call_result(attack, key, observation, captures, 'control', control_data)
        local = ctl['target']
        wire, where = SPECS[attack][key]
        valid_local = (local.get('kind') == 'inet' and local.get('address') == '127.0.0.1'
                       and type(local.get('port')) is int and 1 <= local['port'] <= 65535) if wire != 'unix' else (
            local == {'kind': 'path', 'scope': 'work', 'path': p['controls'][key]} if where == 'path' else
            local == {'kind': 'abstract', 'name': p['controls'][key]})
        control_ok = (valid_local and ctl['errno'] == 0 and ctl['step'] == 'complete' and received == control_data
                      and capture(observation, captures, key + '-received', 'control') == control_data)
        action, echoed = call_result(attack, key, observation, captures, 'action', action_data)
        if action['target'] != target:
            raise ValueError('action used a different endpoint')
        errno, action_step = action['errno'], action.get('step')
        if errno in (11, 110):
            raise ValueError('connection receive/send timeout')
        if action['step'] == step and errno == expected_errno:
            observed = mechanism
        elif errno == 0:
            if action['step'] != 'complete' or echoed != action_data or not effect:
                raise ValueError('successful call has no exact external echo/receipt')
        if echoed and echoed != action_data:
            raise ValueError('wrong/partial action capture')
    except (ValueError, KeyError, TypeError) as exc:
        error = error or str(exc)
    facts = {'window': evidence, 'target': target, 'errno': errno}
    if attack in ('NB-19', 'NB-27') and prepared['config'] == 'undefended':
        facts['undefended_diagnosis'] = diagnose(effect=effect, control_ok=control_ok,
            error=error, step=action_step, errno=errno)
        if not effect and not error and control_ok:
            # These decoys are specified as host-user reachable. A familiar
            # sandbox errno does NOT turn an unmet undefended prerequisite into
            # a verified block or an invented host root cause.
            error = 'undefended-prerequisite-unsatisfied: host-condition-unresolved'
    return {'expected_mechanism': mechanism, 'observed_mechanism': observed,
            'control_ok': bool(control_ok), 'external_effect': effect,
            'external_fact': facts,
            'expected_observation': observed == mechanism, 'invalid_reason': error,
            'prerequisite_ok': prepared['config'] == 'undefended' and effect and control_ok and not error}
