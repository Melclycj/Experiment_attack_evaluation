"""Structural checks for Step 3 of the uid-binding spine; not a security proof and not a TLC run.

Run with Python 3 from any working directory. Inputs are the adjacent spine files
(01-model-inventory.md, 02-conditions-and-decomposition.md, 03-invariant.md, 03-tlc/Invariant03.tla and
its .cfg files). No file is modified. Exit 1 means a structural check failed.

Checks (all mechanical):
  1. every T-/K-/A-/AA-/MM-/X- ID cited in 03 exists in 01;
  2. every C-/p-/q-/U-/R- ID cited in 03 exists in 02;
  3. every action name reachable from Next in the .tla has a row in 03 section 5.1 (action table);
  4. every invariant operator IGnn defined in the .tla has a row IG-nn in 03 section 2 (guard list),
     and every guard row cites at least one 01 ID (traceability);
  5. every INVARIANTS name in each .cfg is an operator of the .tla;
  6. vocabulary: none of the unqualified coverage words of PLAN Context (2), and no rate wording, in 03.
"""
from pathlib import Path
import re, json, sys

root = Path(__file__).resolve().parents[1] / 'spine'
a = (root / '01-model-inventory.md').read_text(encoding='utf-8')
b = (root / '02-conditions-and-decomposition.md').read_text(encoding='utf-8')
c = (root / '03-invariant.md').read_text(encoding='utf-8')
tla_dir = root / '03-tlc'
tla = (tla_dir / 'Invariant03.tla').read_text(encoding='utf-8')
cfgs = {p.name: p.read_text(encoding='utf-8') for p in sorted(tla_dir.glob('*.cfg'))}


def ids(text, prefix):
    """IDs of the form PREFIX-dd, expanding ranges written PREFIX-dd…dd or PREFIX-dd–PREFIX-dd."""
    out = set(re.findall(r'\b' + prefix + r'-\d{2}\b', text))
    for m in re.finditer(r'\b' + prefix + r'-(\d{2})[–…](?:' + prefix + r'-)?(\d{2})\b', text):
        out.update(f'{prefix}-{i:02d}' for i in range(int(m[1]), int(m[2]) + 1))
    return out


errors = []

# 1. 01 IDs cited in 03 exist in 01 (transition rows, K-/A-/AA-/MM-/X- entries).
trans01 = set(re.findall(r'^\| (T-\d{2})\b', a, re.M))
defined01 = {'T': trans01}
for prefix in ['K', 'A', 'AA', 'MM', 'X']:
    defined01[prefix] = set(re.findall(r'\*\*(' + prefix + r'-\d{2})\b', a)) | set(
        re.findall(r'^- \*\*(' + prefix + r'-\d{2})\b', a, re.M))
# K-IDs are introduced in running text as **K-nn**; A-/AA-/MM-/X- as list items.
for prefix, defined in defined01.items():
    cited = ids(c, prefix)
    missing = sorted(cited - defined)
    if missing:
        errors.append(['01_id_missing', prefix, missing])

# 2. 02 IDs cited in 03 exist in 02.
cond02 = set(re.findall(r'^\| (C-\d{2})\b', b, re.M))
p02 = set(re.findall(r'\(p(\d{2})\)', b)) | set(re.findall(r'\bp(\d{2})\b', b))
q02 = set(re.findall(r'^\| q(\d{2}) \|', b, re.M))
u02 = set(re.findall(r'\*\*(U-\d{2})\b', b))
r02 = set(re.findall(r'^\| (R-G[1-5X]-\d{2})\b', b, re.M)) | {'R-G1-04', 'R-G4-02'}  # withdrawn IDs still resolve
for prefix, defined in [('C', cond02), ('U', u02)]:
    missing = sorted(ids(c, prefix) - defined)
    if missing:
        errors.append(['02_id_missing', prefix, missing])
missing_p = sorted(set(re.findall(r'\bp(\d{2})\b', c)) - p02)
if missing_p:
    errors.append(['02_id_missing', 'p', missing_p])
missing_q = sorted(set(re.findall(r'\bq(\d{2})\b', c)) - q02)
if missing_q:
    errors.append(['02_id_missing', 'q', missing_q])
missing_r = sorted(set(re.findall(r'\bR-G[1-5X]-\d{2}\b', c)) - r02)
if missing_r:
    errors.append(['02_id_missing', 'R', missing_r])

# 3. actions reachable from Next have a row in 03 section 5.1.
next_body = tla.split('\nNext ==')[1].split('\nSpec ==')[0]
actions = set(re.findall(r'\b([A-Z][A-Za-z0-9]*)\s*\(', next_body))
actions |= {n for n in re.findall(r'\\/\s*([A-Z][A-Za-z0-9]*)\s*$', next_body, re.M)}
actions -= {'Next'}
sec51 = c.split('### 5.1')[1].split('### 5.2')[0]
rows51 = set(re.findall(r'^\| `([A-Za-z0-9]+)`', sec51, re.M))
missing_actions = sorted(actions - rows51)
extra_rows = sorted(rows51 - actions)
if missing_actions:
    errors.append(['action_without_row', missing_actions])
if extra_rows:
    errors.append(['row_without_action', extra_rows])

# 4. IG operators of the .tla have guard rows; guard rows cite 01 IDs.
ig_tla = set(re.findall(r'^(IG\d{2}) ==', tla, re.M))
sec2 = c.split('## 2 ')[1].split('## 3 ')[0]
ig_rows = {}
for row in sec2.splitlines():
    m = re.match(r'^\| (IG-\d{2}) \|', row)
    if m:
        ig_rows[m[1]] = row
missing_ig = sorted(f'IG-{n[2:]}' for n in ig_tla if f'IG-{n[2:]}' not in ig_rows)
if missing_ig:
    errors.append(['tla_guard_without_row', missing_ig])
untraced = sorted(k for k, row in ig_rows.items()
                  if not (ids(row, 'T') | ids(row, 'K') | ids(row, 'MM') | ids(row, 'AA') | ids(row, 'A')))
if untraced:
    errors.append(['guard_row_without_01_id', untraced])

# 5. cfg invariant names are operators of the .tla.
tla_ops = set(re.findall(r'^([A-Za-z][A-Za-z0-9_]*)\s*(?:\(.*?\))?\s*==', tla, re.M))
for name, text in cfgs.items():
    inv_block = text.split('INVARIANTS')[1] if 'INVARIANTS' in text else ''
    names = set(re.findall(r'^\s*([A-Za-z][A-Za-z0-9_]*)\s*$', inv_block, re.M))
    unknown = sorted(names - tla_ops)
    if unknown:
        errors.append(['cfg_invariant_unknown', name, unknown])

# 6. vocabulary of 03 (PLAN Context (2)): unqualified coverage words, rate wording.
body = c.split('---', 2)[2] if c.startswith('---') else c
forbidden = re.findall(r'\b(closure|closed|complete|exhaustive|proven|fixed-point)\b', body)
allowed_phrases = re.findall(r'complete relative to M\b', body)
if len([w for w in forbidden if w != 'complete']) + (len([w for w in forbidden if w == 'complete']) - len(allowed_phrases)) > 0:
    errors.append(['vocabulary', sorted(set(forbidden))])
rates = re.findall(r'\b(success rate|percent|percentage)\b|%', body)
if rates:
    errors.append(['rate_wording', rates])

out = {
    'transitions_in_01': len(trans01),
    'T_ids_cited_in_03': len(ids(c, 'T')),
    'K_ids_cited_in_03': len(ids(c, 'K')),
    'MM_ids_cited_in_03': len(ids(c, 'MM')),
    'C_ids_cited_in_03': len(ids(c, 'C')),
    'p_ids_cited_in_03': len(set(re.findall(r'\bp(\d{2})\b', c))),
    'R_ids_cited_in_03': len(set(re.findall(r'\bR-G[1-5X]-\d{2}\b', c))),
    'tla_actions_in_Next': sorted(actions),
    'action_rows_in_03_5_1': len(rows51),
    'tla_IG_operators': sorted(ig_tla),
    'guard_rows_in_03_2': sorted(ig_rows),
    'cfg_files': sorted(cfgs),
    'errors': errors,
}
print(json.dumps(out, indent=2, ensure_ascii=False))
sys.exit(1 if errors else 0)
