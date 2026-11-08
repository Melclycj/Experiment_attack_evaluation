"""Table 4.2 of the thesis from the v4 memory analysis. Read-only.
  python -X utf8 table-4.2.py
Each cell: the agent's own part, unshared PSS over the same-round bare-api-only (paired range over repetitions, clean
readings), and the shared group's growth per added agent, (mean shared PSS at N - mean at 1) / (N - 1). The sum at 16 agents
is the main measure of the memory comparison in Chapter 5; at 1 agent there is no added agent, so the cell is the own part alone.
A reading flagged by the protocol leaves both parts: extra_range_clean already omits it, and the shared mean here omits it too.
Source: original/memory/20261105-memory-analysis-engine-v4/memory-analysis.json, state "resident"
(Claude Code at its prompt; the analysis's "idle" state is the k6 rows without an agent).
"""
import json
import statistics
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / 'original/memory/20261105-memory-analysis-engine-v4/memory-analysis.json'
data = json.loads(SOURCE.read_text(encoding='utf-8'))


def clean_shared(tier):
    return [s for s, flags in zip(tier['shared_mib'], tier['flags']) if not flags]


for name in ('engine-v4-shared', 'engine-v4-copy'):
    tiers = data[name + '/resident']['tiers']
    base = statistics.fmean(clean_shared(tiers['1']))
    print(name, 'shared group at 1 agent: mean %.2f' % base)
    for n in ('1', '2', '4', '8', '16'):
        t = tiers[n]
        lo, hi = t['extra_range_clean']
        growth = 0.0 if n == '1' else (statistics.fmean(clean_shared(t)) - base) / (int(n) - 1)
        print('  N=%-2s readings=%d flagged=%d own part %.1f-%.1f growth %.2f  sum %.1f-%.1f' % (
            n, t['readings'], t['flagged'], lo, hi, growth, lo + growth, hi + growth))
