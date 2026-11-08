"""Tally Table 4.1 of the thesis from the formal v4 attack runs. Read-only.

  python -X utf8 tally-table-4.1.py          row table plus exceptions
  python -X utf8 tally-table-4.1.py --all    also every subgoal

Rows and attack ids follow Table 4.1 of the thesis and ATTACKS.md. An attack counts as stopped only when every subgoal
was stopped by the expected mechanism; "escalated" (sent to the user) and any other outcome are listed apart.
A run counts only when run.json has formal=true and engine baseline v4 and its controller did not abort the batch,
and the newest such run wins per subgoal. An undefended attack of the shared harness counts by its row verdict:
NB-23's goal is any one target (no-bypass/tests.md 2.10), so its other targets refusing is not a failure.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

A = Path(__file__).resolve().parent


def ids(prefix, lo, hi):
    return ['%s-%02d' % (prefix, n) for n in range(lo, hi + 1)]


NB, DF, CB = 'no-bypass', 'decision-faithfulness', 'credential-binding'
ROWS = [
    (NB, 'File reads and writes outside the workspace', ids('NB', 1, 11)),
    (NB, 'Other workspaces and repositories', ids('NB', 12, 15)),
    (NB, 'Network around the engine', ids('NB', 16, 18)),
    (NB, 'Sockets of privileged daemons', ['NB-19']),
    (NB, "The monitor's own state", ids('NB', 20, 23)),
    (NB, 'Inherited descriptor', ['NB-24']),
    (NB, 'Abstract socket', ['NB-25']),
    (NB, 'User namespace and veth', ['NB-26']),
    (NB, 'Host service starts a process', ['NB-27']),
    (NB, 'Package script searching for credentials', ['NB-28']),
    (DF, 'One allow or approval used twice', ['DF-01', 'DF-07']),
    (DF, 'Destinations, redirects, approval endpoint, re-resolution', ['DF-03', 'DF-05', 'DF-06', 'DF-09']),
    (DF, 'Answer on a new request; upstream reuse', ['DF-08', 'DF-10']),
    (DF, 'Use after revocation', ['DF-12']),
    (DF, 'Control port, table change, probing, scheme word', ids('DF', 16, 19)),
] + [(CB, 'Public case ' + i, [i]) for i in ids('CB', 1, 6)] + [
    (CB, 'Wrong place, host, account, redirect, HTTP, Host', ids('CB', 7, 12)),
    (CB, 'CB-14 clause 8', ['CB-14']),
]
CONTROLS = {
    NB: ['PC-FILE', 'PC-PROXY', 'PC-DIALOGUE'],
    DF: ['PC-ALLOW', 'PC-FALLBACK', 'PC-ONCE', 'PC-CELL', 'PC-CRED', 'PC-RECHECK', 'PC-STREAM'],
    CB: ['PC-FILE', 'PC-PROXY', 'PC-DIALOGUE', 'PC-CREDENTIAL'],
}
BOUNDARY = ['BD-01', 'BD-02']


def formal_runs(unit):
    root = A / 'original' / unit / 'runs'
    for path in sorted(p for p in root.iterdir() if p.is_dir()):
        head = path / 'run.json'
        results = path / 'results.jsonl'
        if not head.exists() or not results.exists():
            continue
        try:
            run = json.loads(head.read_text(encoding='utf-8'))
        except ValueError:
            continue
        engine = run.get('engine') if isinstance(run.get('engine'), dict) else {}
        if run.get('formal') is True and engine.get('baseline') == 'v4' and not run.get('controller_error'):
            yield path, run, results


def records(results):
    """Yield (attack, subgoal, config, outcome, mechanism, mismatch, reason, kind) for one results file."""
    for line in results.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        kind = r.get('kind', '')
        attack = r.get('attack') or (r.get('subgoal') or '').split('/')[0]
        if r.get('attempts'):  # the shared harness: attempts with targets
            for attempt in r['attempts']:
                for t in attempt.get('targets') or [attempt]:
                    yield (attack, t.get('id', ''), r.get('config'), t.get('outcome'), t.get('observed_mechanism'),
                           t.get('mismatch'), t.get('invalid_reason') or attempt.get('fatal_error') or '', kind)
        else:  # the 3.1 harness: one record per subgoal
            sub = (r.get('subgoal') or attack).split('/')
            yield (attack, sub[1] if len(sub) > 1 else '', r.get('config'), r.get('outcome'),
                   r.get('observed_mechanism'), r.get('mismatch'), r.get('invalid_reason') or '', kind)


def row_verdicts(results):
    """Yield (attack, config, outcome) for the shared harness's rows: the attack's own verdict across its targets."""
    for line in results.read_text(encoding='utf-8').splitlines():
        if line.strip():
            r = json.loads(line)
            if r.get('attempts'):
                yield r.get('attack'), r.get('config'), r.get('outcome')


def main(show_all):
    table = defaultdict(dict)  # (unit, attack, subgoal, config) -> record, newest run wins
    verdicts = {}  # (unit, attack, config) -> row verdict, newest run wins
    seen = defaultdict(set)
    for unit in (NB, DF, CB):
        for path, _run, results in formal_runs(unit):
            seen[unit].add(path.name)
            for attack, sub, config, outcome, mech, mismatch, reason, kind in records(results):
                table[(unit, attack)][(sub, config)] = (outcome, mech, mismatch, reason, kind, path.name)
            for attack, config, outcome in row_verdicts(results):
                verdicts[(unit, attack, config)] = outcome
    for unit in (NB, DF, CB):
        print('%s: %d formal v4 runs' % (unit, len(seen[unit])))
        for name in sorted(seen[unit]):
            print('   ', name)
    print()
    totals = defaultdict(int)
    exceptions = []
    print('%-22s %-58s %3s %4s | %-14s | %-22s' % ('unit', 'row', 'n', 'data', 'undefended ok', 'engine stopped/hand'))
    for unit, label, attacks in ROWS:
        have = reached = stopped = handed = 0
        for attack in attacks:
            subs = table.get((unit, attack))
            if not subs:
                continue
            have += 1
            engine = [v for (s, c), v in subs.items() if c == 'engine']
            bare = [v for (s, c), v in subs.items() if c == 'undefended']
            verdict = verdicts.get((unit, attack, 'undefended'))
            if bare and (verdict == 'succeeded' if verdict else all(v[0] == 'succeeded' for v in bare)):
                reached += 1
            if engine and all(v[0] == 'blocked' for v in engine):
                stopped += 1
            elif engine and all(v[0] in ('blocked', 'escalated') for v in engine):
                handed += 1
            for (s, c), v in sorted(subs.items()):
                standard = (c == 'engine' and v[0] == 'blocked' and not v[2]) or (c == 'undefended' and v[0] == 'succeeded')
                if not standard:
                    exceptions.append((attack, s, c, v[0], v[1], v[2], v[3], v[5]))
        n = len(attacks)
        print('%-22s %-58s %3d %4d | %5d of %-5d | %3d stopped %3d handed' % (unit, label, n, have, reached, have, stopped, handed))
        if 'not in the table' not in label:
            totals['attacks'] += n
            totals['have'] += have
            totals['reached'] += reached
            totals['stopped'] += stopped
            totals['handed'] += handed
    print()
    print('Totals, table rows above without NB-30 (filled by hand from its own run):', dict(totals))
    print('\nLegitimate operations (engine only; outcomes of the newest run per target, not a per-batch check):')
    for unit in (NB, DF, CB):
        for pc in CONTROLS[unit]:
            subs = table.get((unit, pc), {})
            print('  %-22s %-14s %s' % (unit, pc, sorted({v[0] for v in subs.values()}) or 'no data'))
    print('\nBoundary demonstrations:')
    for bd in BOUNDARY:
        subs = table.get((NB, bd), {})
        print('  %s %s' % (bd, {c: v[0] for (s, c), v in subs.items()} or 'no data'))
    print('\nExceptions: not the standard pair (undefended succeeded, engine blocked by the expected mechanism):')
    for row in exceptions:
        print('  %-7s %-24s %-11s %-15s mismatch=%-5s obs=%s %s [%s]' % (
            row[0], row[1], row[2], row[3], row[5], str(row[4])[:60], str(row[6])[:120], row[7]))
    if show_all:
        print('\nEvery subgoal:')
        for (unit, attack), subs in sorted(table.items()):
            for (s, c), v in sorted(subs.items()):
                print('  %-7s %-24s %-11s %-15s %s' % (attack, s, c, v[0], str(v[1])[:70]))


if __name__ == '__main__':
    main('--all' in sys.argv)
