"""Structural traceability and local Boolean split checks; not a security proof.

Run with Python 3, from any working directory. Inputs are the adjacent spine.
No file is modified. Exit 1 means a structural check failed.
"""
from pathlib import Path
import re,json,collections,itertools
root=Path(__file__).resolve().parents[1]/'spine'
a=(root/'01-model-inventory.md').read_text(encoding='utf-8')
b=(root/'02-conditions-and-decomposition.md').read_text(encoding='utf-8')
def ids(s,prefix):
    out=set(re.findall(r'\b'+prefix+r'-\d{2}\b',s))
    for m in re.finditer(r'\b'+prefix+r'-(\d{2})[–…](?:'+prefix+r'-)?(\d{2})\b',s):
        out.update(f'{prefix}-{i:02d}' for i in range(int(m[1]),int(m[2])+1))
    return out
trans=set(re.findall(r'^\| (T-\d{2})\b',a,re.M))
cut=b.split('## 7 Group cut')[1].split('Attribution-irrelevant exclusions')[0]
owners=collections.defaultdict(list)
for row in cut.splitlines():
    if re.match(r'^\| G[1-5] ',row):
        cells=row.split('|'); group=cells[1].strip().split()[0]
        for t in ids(cells[2],'T'): owners[t].append(group)
ledger=b.split('## 6 Route ledger')[1].split('## 7 Group cut')[0]
routes={}
for row in ledger.splitlines():
    if re.match(r'^\| R-G',row):
        cells=[x.strip() for x in row.split('|')[1:-1]]
        rid=cells[0]
        assert rid not in routes,rid
        routes[rid]={'conditions':sorted(ids(cells[3],'C')),'group':cells[4],'transitions':sorted(ids(cells[5],'T'))}
matrix=b.split('## 8 Condition')[1]
seen=collections.defaultdict(set); bad=[]
for row in matrix.splitlines():
    if re.match(r'^\| C-\d',row):
        cells=[x.strip() for x in row.split('|')[1:-1]]; cond=cells[0]
        for group,cell in zip(['G1','G2','G3','G4','G5','GX'],cells[1:]):
            if cell.startswith('no route:'):continue
            last=None
            for token in cell.split(','):
                token=token.strip()
                m=re.match(r'(G[1-5X])-(\d{2})',token)
                if m:last=m[1]; n=m[2]
                else:
                    m=re.match(r'(\d{2})',token)
                    if not m:bad.append(['unparsed',cond,group,token]);continue
                    n=m[1]
                rid=f'R-{last}-{n}'
                seen[rid].add(cond)
                if rid not in routes:bad.append(['unknown_route',rid])
                elif routes[rid]['group']!=group:bad.append(['wrong_group',rid,group])
for rid,r in routes.items():
    if seen[rid]!=set(r['conditions']):bad.append(['condition_mismatch',rid,r['conditions'],sorted(seen[rid])])
touched=set().union(*(set(r['transitions']) for r in routes.values()))
out={'transition_count':len(trans),'route_count':len(routes),'route_groups':dict(collections.Counter(r['group'] for r in routes.values())),
'missing_transition_owners':sorted(trans-set(owners)), 'extra_transition_owners':sorted(set(owners)-trans),
'duplicate_transition_owners':{k:v for k,v in owners.items() if len(v)!=1},
'transitions_without_ledger_trace':sorted(trans-touched),'matrix_errors':bad,
'unknown_ledger_transitions':sorted(touched-trans)}
# Check every named component and route destination in the written split.
# These truth tables treat selectors as independent booleans; they do not
# validate that the causal selectors correctly describe real executions.
conditions=b.split('## 2 Sufficient conditions')[1].split('## 3 Sufficiency')[0]
expected_components={f'D_{m[1]}{m[2]}' for m in re.finditer(r'\(p([1-8])([1-3])\)',conditions)}
selectors=b.split('### Selector vocabulary')[1].split('### Total branch assignment')[0]
declared_selectors=set(re.findall(r'^\| (q\d{2}) \|',selectors,re.M))
branches=b.split('### Total branch assignment')[1].split('### 4.1')[0]
components=[]; assigned=set(); split_errors=[]; valuations=0
for row in branches.splitlines():
    if not re.match(r'^\| D_\d{2} ',row):continue
    cells=[c.strip() for c in row.split('|')[1:-1]]
    component,body=cells;components.append(component)
    clauses=re.findall(r'(?:^|;)\s*(.*?)\s*→\s*(R-G[1-5X]-\d{2})[^;]*',body)
    used=set(re.findall(r'q\d{2}',body))
    if used-declared_selectors:split_errors.append(['undeclared_selector',component,sorted(used-declared_selectors)])
    assigned.update(route for expr,route in clauses)
    for values in itertools.product([False,True],repeat=len(used)):
        env=dict(zip(sorted(used),values));hits=[]
        for expr,route in clauses:
            if expr=='else':hit=not any(hits)
            elif expr=='true':hit=True
            else:
                # Restricted evaluator for the documented q/NOT/AND/OR syntax.
                tokens=re.findall(r'q\d{2}|NOT|AND|OR|[()]',expr)
                if ''.join(tokens)!=re.sub(r'\s+','',expr):raise ValueError(expr)
                code=' '.join(str(env[t]) if t in env else {'NOT':'not','AND':'and','OR':'or'}.get(t,t) for t in tokens)
                hit=bool(eval(code,{'__builtins__':{}},{}))
            hits.append(hit)
        valuations+=1
        if sum(hits)!=1:split_errors.append(['not_exactly_one',component,env,hits])
assigned.update(['R-G5-01','R-G5-02']) # explicit H partition below the table
if set(components)!=expected_components:split_errors.append(['component_set',sorted(expected_components-set(components)),sorted(set(components)-expected_components)])
if len(components)!=len(set(components)):split_errors.append(['duplicate_component'])
if assigned!=set(routes):split_errors.append(['route_destinations',sorted(set(routes)-assigned),sorted(assigned-set(routes))])
out.update({'component_count':len(components),'selector_count':len(declared_selectors),
            'local_split_valuations_checked':valuations,'split_errors':split_errors})
print(json.dumps(out,indent=2))
assert not split_errors
assert not any(out[k] for k in ['missing_transition_owners','extra_transition_owners','duplicate_transition_owners','transitions_without_ledger_trace','matrix_errors','unknown_ledger_transitions'])
