"""Idle memory of the two frontends after 'ready': same launch form (the gate's: --ca-dir), same wait, one read each."""
import json, os, socket, subprocess, sys, tempfile, time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
VENV_PY = Path.home() / '.venvs/engine-v2-frontend/bin/python'
GO_BIN = sys.argv[1]
OUT = Path(sys.argv[2])
IDLE_S = 5.0

work = Path(tempfile.mkdtemp(prefix='w2-frontend-mem-'))
subprocess.run([str(VENV_PY), '-I', '-B', str(ENGINE / 'frontend/make_ca_pool.py'), str(work / 'pool'), '1'], check=True)
entry = next(p for p in (work / 'pool').iterdir() if p.is_dir())
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(str(work / 'proxy.sock'))
listener.listen(8)

def free_port() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def measure(label: str, command: list[str]) -> dict:
    port, ready = free_port(), work / f'ready-{label}'
    argv = [*command, '--confdir', str(work / f'conf-{label}'), '--ca-dir', str(entry), str(work / 'proxy.sock'), str(port), str(ready)]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    t0 = time.monotonic()
    while not ready.exists() and proc.poll() is None and time.monotonic() - t0 < 30:
        time.sleep(0.01)
    ready_after = time.monotonic() - t0
    assert ready.exists(), (label, proc.poll())
    time.sleep(IDLE_S)
    rollup = Path(f'/proc/{proc.pid}/smaps_rollup').read_text()
    status = Path(f'/proc/{proc.pid}/status').read_text()
    cmdline = Path(f'/proc/{proc.pid}/cmdline').read_bytes().split(b'\0')[0].decode()
    proc.terminate()
    proc.wait(10)
    fields = {}
    for line in rollup.splitlines()[1:]:
        name, value = line.split(':', 1)
        fields[name.strip()] = int(value.split()[0])
    st = {k: v.strip() for k, v in (l.split(':', 1) for l in status.splitlines()) if k in ('Threads', 'VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'RssShmem')}
    return dict(label=label, argv=argv, exe=cmdline, ready_after_s=round(ready_after, 3), idle_s=IDLE_S, smaps_rollup_kB=fields, status=st)

results = [measure('python', [str(VENV_PY), '-I', '-B', str(ENGINE / 'frontend/engine_frontend.py')]),
           measure('go', [GO_BIN])]
record = dict(when=time.strftime('%Y-%m-%dT%H:%M:%S%z'), kernel=os.uname().release, results=results)
OUT.write_text(json.dumps(record, indent=1))
for r in results:
    f = r['smaps_rollup_kB']
    print(f"{r['label']:7s} ready {r['ready_after_s']}s  Rss {f['Rss']} kB  Pss {f['Pss']} kB  Private_Clean {f['Private_Clean']} kB  "
          f"Private_Dirty {f['Private_Dirty']} kB  Shared_Clean {f['Shared_Clean']} kB  Threads {r['status']['Threads']}")
