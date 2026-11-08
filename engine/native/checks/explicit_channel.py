"""Explicit channels between the host and the cell, measured once per sandbox regression.

Workspace (the workspace rework, validation.md D-17 and S-25; it replaces phase 2's D-14 probe, in which a host-user
process's Unix socket and FIFO in a host-user-owned workspace were reachable from the cell): the storage belongs to a
dedicated uid, root 0700, the cell mounts the fixed subdirectory. The host user tries to put a file, a FIFO, a socket
and a hard link into it before a row runs and after the row has opened what the cell uid can (/work to 0777, a setuid
file); every attempt must fail. Asserted.
Read-only mount (D-16): a host-user process's Unix socket and FIFO behind a plain read-only bind mount
(remount,bind,ro,nosuid,nodev, the way /w2 and /runtime are mounted in the cell), reached by an unprivileged uid: kernel
semantics, not a cell. Outcomes recorded, not asserted; only the probe's preconditions are.
"""
import errno
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

DROP = ['/usr/bin/setpriv', '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
        '--no-new-privs']
HOST_UID = 1000         # the host user: owns the workspaces of the test deployment
PROBER_UID = 70002      # a pool test uid (the runner checks it is no host account), an unrelated unprivileged process

# Run as the host user: makes <dir>/host.sock (listening) and <dir>/host.fifo (open for reading) under the given
# umask, prints one line with what it made, then collects what arrives on either until both have spoken or the
# deadline passes, and prints that.
HOST_END = r'''
import json, os, socket, struct, sys, time
d, deadline = sys.argv[1], time.monotonic() + float(sys.argv[2])
os.umask(int(sys.argv[3], 8))
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
listener.bind(d + '/host.sock')
listener.listen(1)
listener.settimeout(0.05)
os.mkfifo(d + '/host.fifo', 0o666)
fifo = os.open(d + '/host.fifo', os.O_RDONLY | os.O_NONBLOCK)
made = {n: {'mode': oct(os.lstat(d + '/' + n).st_mode & 0o7777), 'uid': os.lstat(d + '/' + n).st_uid}
        for n in ('host.sock', 'host.fifo')}
print(json.dumps({'uid': os.getuid(), 'made': made}), flush=True)
seen = {'accepted': False, 'peer_uid': None, 'peer_gid': None, 'sock_bytes': '', 'fifo_bytes': ''}
while time.monotonic() < deadline and not (seen['sock_bytes'] and seen['fifo_bytes']):
    if not seen['accepted']:
        try:
            conn = listener.accept()[0]
        except socket.timeout:
            pass
        else:
            seen['accepted'] = True
            _, seen['peer_uid'], seen['peer_gid'] = struct.unpack(
                '3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            conn.settimeout(2)
            seen['sock_bytes'] = conn.recv(64).decode()
    try:
        seen['fifo_bytes'] += os.read(fifo, 64).decode()
    except BlockingIOError:
        pass
    time.sleep(0.05)
print(json.dumps(seen), flush=True)
'''

# Run as PROBER_UID against the read-only view: the two objects, then two writes the read-only mount must refuse.
PROBE = r'''
import json, os, socket, sys
d, out = sys.argv[1], {}
def attempt(name, action):
    try:
        out[name] = {'result': action(), 'errno': 0}
    except OSError as error:
        out[name] = {'result': -1, 'errno': error.errno}
def sock():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(d + '/host.sock')
    return s.send(b'ro-sock')
def fifo():
    return os.write(os.open(d + '/host.fifo', os.O_WRONLY | os.O_NONBLOCK), b'ro-fifo')
attempt('sock_connect_send', sock)
attempt('fifo_open_write', fifo)
attempt('plain_open_write', lambda: os.open(d + '/plain', os.O_WRONLY) and 0)
attempt('create', lambda: os.open(d + '/new', os.O_WRONLY | os.O_CREAT, 0o644) and 0)
print(json.dumps(out))
'''


def _host_end(directory, mask):
    p = subprocess.Popen(DROP + [f'--reuid={HOST_UID}', f'--regid={HOST_UID}', '/usr/bin/python3', '-I', '-c',
                                 HOST_END, str(directory), '30', mask], stdout=subprocess.PIPE, text=True)
    return p, json.loads(p.stdout.readline())


def _collect(p):
    out, _ = p.communicate(timeout=40)
    assert p.returncode == 0, p.returncode
    return json.loads(out.splitlines()[-1])


def _stop(p):
    if p.poll() is None:
        p.kill()
        p.wait(timeout=5)


# Run as the host user against the workspace storage: every way of putting something into it, each outcome by errno.
HOST_TRY = r'''
import json, os, socket, sys
out = {}
def attempt(name, action):
    try:
        action()
        out[name] = 0
    except OSError as error:
        out[name] = error.errno
for d in sys.argv[1:]:
    attempt(d + ' file', lambda: os.close(os.open(d + '/host-file', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)))
    attempt(d + ' fifo', lambda: os.mkfifo(d + '/host-fifo'))
    attempt(d + ' socket', lambda: socket.socket(socket.AF_UNIX).bind(d + '/host-sock'))
    attempt(d + ' hardlink', lambda: os.link(d + '/persistent', d + '/host-link'))
    attempt(d + ' exec-setuid', lambda: os.execv(d + '/door-setuid', [d + '/door-setuid']))
print(json.dumps(out))
'''


def measure(root_dir, tree, owner, run_cell, cell_report, command):
    """The workspace rework (validation.md D-17, S-25; agent-rm-model 3.1, 6.2 uid 行), replacing the D-14 probe:
    root_dir is a workspace root (owner's, 0700) and tree its fixed subdirectory, the one run_cell()'s row mounts. The
    host user (uid 1000, no capability) tries to make a file, a FIFO, a Unix socket and a hard link there, before the
    row and after the row has opened what the cell uid can (/work to 0777, a setuid file of its own, asked by a request
    file); every attempt must fail, and the root must still be 0700. cell_report(): the row's report.txt as read."""
    def host_try(*dirs):
        done = command(DROP + [f'--reuid={HOST_UID}', f'--regid={HOST_UID}', '/usr/bin/python3', '-I', '-c',
                               HOST_TRY, *map(str, dirs)])
        return json.loads(done['stdout'])
    before = host_try(root_dir, tree)
    request = tree / '.open-the-door'
    request.touch(mode=0o600)
    os.chown(request, owner, owner)
    try:
        run_cell()
        report = cell_report()
        door = dict(re.findall(r'^(door_\w+)=(-?\d+ errno=\d+)$', report, re.M))
        after_modes = {'root': oct(os.stat(root_dir).st_mode & 0o7777), 'root_uid': os.stat(root_dir).st_uid,
                       'tree': oct(os.stat(tree).st_mode & 0o7777),
                       'setuid_file': oct(os.stat(tree / 'door-setuid').st_mode & 0o7777)}
        after = host_try(tree)
    finally:
        tree.chmod(0o700)
        for name in ('.open-the-door', 'door-setuid'):
            (tree / name).unlink(missing_ok=True)
    assert door == {'door_work_chmod': '0 errno=0', 'door_setuid_file': '0 errno=0'}, door       # the cell could
    assert after_modes['tree'] == '0o777' and after_modes['setuid_file'] == '0o4755', after_modes
    assert after_modes['root'] == '0o700' and after_modes['root_uid'] == owner, after_modes       # the door held
    assert all(e == errno.EACCES for e in before.values()) and all(e == errno.EACCES for e in after.values()), (before, after)
    assert 'persistent_existed=' in report                       # the cell read and wrote as before
    record = {'workspace': {'host_before': before, 'cell_opened': door, 'after_the_cell': after_modes,
                            'host_after': after}}
    top = Path(tempfile.mkdtemp(prefix='w2-p2a-ro-', dir='/tmp'))
    try:
        top.chmod(0o755)
        source, view = top / 'source', top / 'view'
        source.mkdir(mode=0o755)
        view.mkdir(mode=0o755)
        os.chown(source, HOST_UID, HOST_UID)
        (source / 'plain').write_text('x')
        (source / 'plain').chmod(0o666)
        command(['/usr/bin/mount', '--bind', source, view])
        try:
            command(['/usr/bin/mount', '-o', 'remount,bind,ro,nosuid,nodev', view])
            host, made = _host_end(source, '000')
            try:
                probe = command(DROP + [f'--reuid={PROBER_UID}', f'--regid={PROBER_UID}', '/usr/bin/python3', '-I',
                                        '-c', PROBE, view])
                seen = _collect(host)
            finally:
                _stop(host)
        finally:
            command(['/usr/bin/umount', view])
        tried = json.loads(probe['stdout'])
        # the precondition: the view refuses writes to this uid, whom the 0666 modes would otherwise let in
        assert tried['plain_open_write']['errno'] == tried['create']['errno'] == errno.EROFS, tried
        record['read_only_mount'] = {'qualification': 'kernel semantics, not a cell: a read-only bind mount reached '
                                                      'by an unprivileged uid',
                                     'host_end': made, 'host_saw': seen, 'prober_saw': tried}
    finally:
        shutil.rmtree(top)
    return record
