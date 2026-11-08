"""Check the files kept as originals against the digests that the run records hold. Read-only, standard library only.

  python3 verify.py

What it checks:
  1. engine/ against every record that lists the engine's files: the attack batches (per-file sha256, or the
     decision-faithfulness batches' combined digest) and the memory and latency runs (per-file sha256).
  2. Each attack batch's test specification (tests*.md of its unit) against the digest in its run.json.
  3. Each attack batch's harness and attack scripts against the digests in its run.json.
  4. Every file of a run archive that has a COMPLETE.json against that manifest.
A digest records what ran; a mismatch means the file here is not the one that ran. Exit status 1 if any check fails.
The earlier batches ran an earlier revision of two harness files; those revisions are kept in
attacks/original/harness-earlier/, and a harness file matches if it equals either revision. The self-check batches ran on deliberately weakened copies of the engine. For them, every file outside the weakening
patch must match engine/, and the patched files must be exactly the ones the patch names.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE / 'engine'
ATTACKS = HERE / 'attacks' / 'original'
UNITS = ('no-bypass', 'credential-binding', 'decision-faithfulness')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()


def tree(root, skip=('__pycache__',)):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob('*'))
            if p.is_file() and not set(p.relative_to(root).parts) & set(skip)}


def patched_files(patch):
    """Paths a unified diff changes, from its +++ lines."""
    return {m.group(1).decode() for m in re.finditer(rb'^\+\+\+ [^/\s]+/(\S+)', patch, re.M)}


def compare_any(have, earlier, want, key):
    """As compare(), but a file also matches if it equals the earlier revision kept for it."""
    problems = [f'missing {r}' for r in sorted(set(want) - set(have))]
    problems += [f'extra {r}' for r in sorted(set(have) - set(want))]
    problems += [f'differs {r}' for r in sorted(set(want) & set(have))
                 if want[r] not in {key(have[r])} | {key(b) for b in earlier.get(r, [])}]
    return problems


def compare(have, want, key):
    """have: {rel: bytes}; want: {rel: digest}; key: function bytes -> digest. Returns a list of problems."""
    problems = [f'missing {r}' for r in sorted(set(want) - set(have))]
    problems += [f'extra {r}' for r in sorted(set(have) - set(want))]
    problems += [f'differs {r}' for r in sorted(set(want) & set(have)) if key(have[r]) != want[r]]
    return problems


def main():
    engine = tree(ENGINE)
    earlier = {}
    for rel, data in tree(ATTACKS / 'harness-earlier').items():
        earlier.setdefault(rel, []).append(data)
    failures, lines = [], []

    def report(name, problems):
        status = 'FAIL' if problems else 'ok'
        lines.append(f'{status:8} {name}' + ('' if not problems else f'  ({len(problems)}: {", ".join(problems[:3])})'))
        if problems:
            failures.append(name)

    # 1 and 2 and 3: attack batches
    for unit in UNITS:
        unit_dir = ATTACKS / unit
        specs = {p.name: p.read_bytes() for p in unit_dir.glob('tests*.md')}
        harness_dir = unit_dir / 'harness' if unit == 'decision-faithfulness' else ATTACKS / 'harness'
        for run_json in sorted((unit_dir / 'runs').glob('*/run.json')):
            run = json.loads(run_json.read_bytes())
            name = f'{unit}/{run_json.parent.name}'
            if unit == 'decision-faithfulness':
                inventory = {r: blob(b) for r, b in engine.items()}
                weakened = run.get('variant_patch') or []
                for change in weakened:
                    inventory[change['file']] = change['blob']
                combined = blob(json.dumps(inventory, sort_keys=True).encode())
                ok = run['engine'].get('digest') == combined and int(run['engine'].get('files', -1)) == len(engine)
                label = 'engine*' if weakened else 'engine'
                report(f'{label:9} vs {name}', [] if ok else ['combined digest differs'])
                spec_ok = any(blob(b) == run.get('spec') for b in specs.values())
                report(f'spec      vs {name}', [] if spec_ok else [f'no tests*.md with blob {run.get("spec")}'])
                hz = {p.name: p.read_bytes() for p in harness_dir.glob('*.py')}
                report(f'harness   vs {name}', compare(hz, run['harness'], blob))
                sc = {p.name: p.read_bytes() for p in (unit_dir / 'scripts').glob('*.py')}
                report(f'scripts   vs {name}', compare(sc, run['scripts'], blob))
            else:
                want = {r: v['sha256'] for r, v in run['configs']['engine']['files'].items()}
                problems = compare(engine, want, sha256)
                label = 'engine'
                if run.get('variant'):
                    label = 'engine*'
                    patch = run_json.parent / run['variant_provenance']['file']
                    touched = patched_files(patch.read_bytes())
                    differing = {p.split(' ', 1)[1] for p in problems if p.startswith('differs ')}
                    problems = [p for p in problems if not p.startswith('differs ')]
                    if differing != touched:
                        problems.append(f'patched {sorted(differing)} but the patch names {sorted(touched)}')
                report(f'{label:9} vs {name}', problems)
                spec = run.get('spec') or {}
                spec_ok = any(sha256(b) == spec.get('sha256') for b in specs.values())
                report(f'spec      vs {name}', [] if spec_ok else [f'no tests*.md with sha256 {spec.get("sha256", "")[:12]}'])
                want_h = {r: v['sha256'] for r, v in run['harness']['files'].items()}
                skip = tuple(run['harness'].get('excluded', ())) or ('__pycache__',)
                report(f'harness   vs {name}', compare_any(tree(harness_dir, skip), earlier, want_h, sha256))

    # 1: memory and latency runs
    for dep in sorted((HERE / 'utility-and-cost' / 'original').rglob('deployment.json')):
        files = json.loads(dep.read_bytes()).get('engine_files')
        if files:
            report(f'engine    vs {dep.relative_to(HERE).parent.as_posix()}', compare(engine, files, sha256))

    # 4: archive manifests
    for manifest in sorted(HERE.rglob('COMPLETE.json')):
        if ENGINE in manifest.parents:
            continue
        listed = json.loads(manifest.read_bytes())['files']
        run_dir = manifest.parent
        have = {r: b for r, b in tree(run_dir).items() if r != 'COMPLETE.json'}
        report(f'archive   {run_dir.relative_to(HERE).as_posix()}', compare(have, {r: v['sha256'] for r, v in listed.items()}, sha256))

    print('\n'.join(lines))
    print(f'\n{len(lines)} checks: {len(failures)} failed')
    print('engine* marks a self-check batch on a weakened copy: the files outside its patch match engine/.')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
