"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import errno
import base64
from pathlib import Path
from types import SimpleNamespace
from case_io import capture, event, closed_window
from common import identity, json_bytes
from decoys import snapshot, changed
from cell.nb_file_spec import WRITES, pathname


def same_object(seen, expected):
    return isinstance(seen, dict) and all(type(seen.get(k)) is int and seen[k] == expected[k] for k in ('dev', 'ino'))


def view_context(prepared, cwd):
    return SimpleNamespace(request=prepared['request'], cwd=cwd,
        target=lambda key, kind: prepared['targets'][key], path=lambda key: prepared['targets'][key]['path'])


def checked_event(observed, key, phase, path):
    result = event(observed, key + '-result', phase)
    if (result.get('valid') is not True or result.get('path') != path
            or type(result.get('errno')) is not int or result.get('signal') is not None):
        raise ValueError('missing/mismatched file operation diagnostic')
    return result


def observe_files(adapter, prepared, observation, captures, window):
    attack, rt, p = adapter.attack, adapter.rt, prepared['parameters']
    requests = closed_window(window, prepared['request']['sync']['nonce'])
    scans = [tree.scan() for tree in adapter.trees]
    # Store verbose tree facts once, not repeated into every result target (16 KiB row limit).
    tree_receipt = rt.evidence.raw(json_bytes({'before': prepared['before']['trees'], 'after': scans}), 'file-trees.json')
    outer_changed = scans[1] != prepared['before']['trees'][1]
    ctx = view_context(prepared, '/work' if prepared['config'] == 'engine' else str(rt.work))
    facts = {}
    for key, target in prepared['targets'].items():
        before, ctl = prepared['before']['targets'][key], prepared['before']['controls'][key]
        after, control_after = snapshot(Path(target['path'])), snapshot(Path(ctl['path']))
        effect, control_ok, seen, problem = False, False, None, ''
        cap, home_cap = None, None
        try:
            action_data = capture(observation, captures, key)
            cap = identity(action_data)
            marker = prepared['tokens'][key].encode()
            upstream_hit = any(marker in json_bytes(req) or marker in base64.b64decode(req.get('payload_base64', ''), validate=True) for req in requests)
            effect = changed(before, after) if attack in WRITES else marker in action_data or upstream_hit
            control_data = capture(observation, captures, key, 'control')
            control_seen = checked_event(observation, key, 'control', pathname(ctx, attack, key, True))
            control_ok = (control_seen['errno'] == 0 and same_object(control_seen.get('identity'), control_after)
                          and (changed(ctl['before'], control_after) if attack in WRITES
                               else p['control_sentinel'].encode() in control_data))
            seen = checked_event(observation, key, 'action', pathname(ctx, attack, key))
            # Read aliases share one inode/token. A shared-window upstream hit
            # alone cannot prove which pathname read it. Keep the leak candidate,
            # but require this path's own capture before assigning that effect.
            if (attack not in WRITES and upstream_hit and marker not in action_data
                    and list(prepared['tokens'].values()).count(prepared['tokens'][key]) > 1):
                problem = 'shared-marker-upstream-effect-not-attributable-to-path'
            if seen['errno'] == 0 and not same_object(seen.get('identity'), before):
                problem = 'successful-call-object-mismatch'
            if attack == 'NB-28':
                home = event(observation, 'home-enumeration')
                required = prepared['config'] == 'undefended'
                if home.get('performed') is not required:
                    raise ValueError('HOME enumeration applicability mismatch')
                if required:
                    data = capture(observation, captures, 'home-' + key)
                    home_seen = checked_event(observation, 'home-' + key, 'action', target['path'])
                    home_cap = identity(data)
                    if not (marker in data and home_seen['errno'] == 0 and same_object(home_seen.get('identity'), before)):
                        problem = 'HOME-alias-prerequisite-failed'
            if attack not in WRITES and outer_changed:
                problem = problem or 'read-only-decoy-tree-changed'
            if attack in WRITES:
                # Only this target may change; additions elsewhere invalidate the verdict.
                rel = next((x for x in adapter.trees[1].files
                            if str(target['path']).endswith('/' + x)), None)
                old, new = prepared['before']['trees'][1], scans[1]
                if {k: v for k, v in old.items() if k != rel} != {k: v for k, v in new.items() if k != rel}:
                    problem = problem or 'unexpected-file-tree-change'
        except (ValueError, KeyError, TypeError, OSError) as exc:
            problem = str(exc)
            # Preserve externally witnessed writes even if cell observations broke.
            effect = changed(before, after) if attack in WRITES else effect
        code = seen.get('errno') if seen else None
        mechanism = 'file-view' if code == errno.ENOENT else 'file-permissions' if code == errno.EACCES else None
        detail = rt.evidence.raw(json_bytes({'before': before, 'after': after, 'control_after': control_after,
            'capture': cap, 'home_capture': home_cap, 'trees': tree_receipt, 'diagnostic': seen}), 'file-fact.json')
        facts[key] = {'expected_mechanism': 'file-view', 'observed_mechanism': mechanism,
            'control_ok': control_ok, 'external_effect': bool(effect),
            'expected_observation': code == errno.ENOENT,
            'invalid_reason': problem,
            'prerequisite_ok': bool(prepared['config'] == 'undefended' and effect and control_ok and not problem),
            'external_fact': {'evidence': detail}}
    return facts
