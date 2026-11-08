"""Mechanical correspondence only; not an independent semantic design review."""
from pathlib import Path
import json
import re
import subprocess
import sys

implementation = Path(__file__).resolve().parents[1]
design = implementation.parents[1] / 'lab/experiments/w2/implementation/engine-design'  # design stays in W2
connections = (design / 'connections.md').read_text(encoding='utf-8-sig')
header = (implementation / 'sandbox/contract.h').read_text(encoding='utf-8-sig')
support = (design / 'supporting-interfaces.md').read_text(encoding='utf-8-sig')
stage_text = re.search(r'`stage` 使用固定枚举：(.*?)；`error_code`', connections, re.S)
if not stage_text:
    raise SystemExit('Cannot locate the normative stage list')
stages = re.sub(r'\s+', '', stage_text[1]).split('/')
result = subprocess.run([sys.argv[1], '--stages'], capture_output=True, text=True, check=True)
actual = [line.split(' ', 1) for line in result.stdout.splitlines()]
if actual != [[str(i), name] for i, name in enumerate(stages, 1)]:
    raise SystemExit('Compiled bootstrap stage numbers/names differ from E-01')
REMOVED_IN_V2 = {('RuntimeDescriptor', 'adapter_id')}
for source_name, c_name in [('LaunchPlan', 'w2_launch_plan'), ('RuntimeDescriptor', 'w2_runtime_descriptor_view')]:
    row = next(line for line in support.splitlines() if line.startswith('| `' + source_name + '` |'))
    fields = re.search(r'\| `([^`]+)`；', row)[1]
    body = re.search(r'struct ' + c_name + r' \{(.*?)\};', header, re.S)[1]
    # argv/env use pointer+count in the C view, all other source fields retain names. v2 removed the descriptor's
    # adapter_id with the hello it served (build plan 7.3; validation.md 第 7 块记录); the W2 design keeps it.
    for field in fields.split(','):
        field = field.strip().split(':', 1)[0]
        if (source_name, field) in REMOVED_IN_V2:
            continue
        if not re.search(r'\b' + re.escape(field) + r'\b', body):
            raise SystemExit(f'{source_name}.{field} missing from C declaration')
print(json.dumps({'check': 'SC-types/source-correspondence', 'result': 'passed',
                  'scope': 'compiled stage mapping and declared field names only; not parser validation'}))
