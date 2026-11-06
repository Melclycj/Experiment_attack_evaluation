"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# The engine row's terminal stream (tests.md 1.3, trace row): the cell's runner and
# every child it does not redirect write to the row's pty, which the in-cell relay
# forwards only to an attached client and drops otherwise. One production attach
# client per engine row is opened before the cell passes its gate (cell/cb_handshake)
# and read until the relay closes; its stdout is the captured stream.
import secrets
from common import identity
from upstream import wait_for

RELAY_CLOSED = b'the relay closed the connection'
LIMITS = ('client removes OSC 52 sequences before its stdout (engine A-06); '
          'bytes before the gate are the fixed runner preamble, which writes no stdio on its success path')


def gate():
    return 'nb-decoy-terminal-' + secrets.token_hex(24)


def open_terminal(handle, value):
    """Row.attach waits for ACTIVE and the socket under the attempt deadline; the cell
    cannot pass its gate, so cannot act, before this client is the relay's one client."""
    stream = handle.attach()
    stream.send((value + '\n').encode())
    return stream


def finish_terminal(rt, stream, value, *, timeout=10):
    """After the row's process tree is gone the relay has exited: the client must see
    the relay's EOF and exit 0 on its own. Anything else is an incomplete capture."""
    child = stream.child
    reason = ''
    try:
        wait_for(rt.command, lambda: child.proc.poll() is not None and not child.streams, timeout=timeout)
    except (TimeoutError, RuntimeError, OSError, ValueError) as exc:
        reason = 'attach client did not end: ' + type(exc).__name__
    code = child.proc.poll()
    if code is not None:
        stream.command.close_input(child)
        stream.closed = True  # exited on its own; Interaction.close would only re-wait it
    data, errors = bytes(child.buffers['stdout']), bytes(child.buffers['stderr'])
    echo = (value + '\r\n').encode()
    last = errors.strip().rsplit(b'\n', 1)[-1].strip()
    if not reason and code != 0:
        reason = 'attach client exit ' + str(code)
    if not reason and not last.startswith(RELAY_CLOSED):
        reason = 'attach ended other than by relay EOF'
    if not reason and not data.startswith(echo):
        reason = 'gate echo absent at capture start'
    return {'data': data, 'complete': not reason, 'reason': reason,
            'provenance': {'source': 'engine-client attach (pipe mode)', 'gate': identity(echo),
                           'exit_code': code, 'client_stderr': identity(errors), 'limits': LIMITS}}
