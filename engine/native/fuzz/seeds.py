"""Write the seed corpora for the three fuzz entries (native/fuzz/fuzz_*.c) into OUT/{frame,ancillary,control}.

Seeds are valid or near-valid inputs in each harness's own format, so the fuzzer starts past the
first checks: whole and fragmented data frames, a frame with rights attached, an out-of-band byte, a
mismatched uid; credential and rights control messages; one record of each control type.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path

EPOCH = '0123456789abcdef0123456789abcdef'
EXECUTION = EPOCH + ':1'
DIGEST = 'sha256:' + '0' * 64


def body(obj: dict) -> bytes:
    return json.dumps(obj, separators=(',', ':')).encode()


def frame(obj: dict) -> bytes:
    b = body(obj)
    return struct.pack('>I', len(b)) + b


def op(kind: int, payload: bytes = b'') -> bytes:
    if kind in (0, 1):
        return bytes([kind]) + struct.pack('>H', len(payload)) + payload
    return bytes([kind])


def frame_seeds() -> dict[str, bytes]:
    hello = frame({'v': 2, 'type': 'hello', 'protocol': 'w2-local/2', 'agent': {'runtime': 'fixture'}})
    request = frame({'v': 2, 'type': 'request', 'id': '1', 'task_call_id': '7', 'task_id': 't1',
                     'resource_id': 'test-doc', 'action': 'document.read', 'args': {}, 'timeout_ms': 1000})
    return {
        'whole': b'\x00' + op(0, hello),
        'two-frames': b'\x00' + op(0, hello + request),
        'header-split': b'\x00' + op(0, hello[:1]) + op(0, hello[1:4]) + op(0, hello[4:20]) + op(0, hello[20:]),
        'rights': b'\x00' + op(1, hello),
        'oob': b'\x00' + op(0, hello[:10]) + op(2) + op(0, hello[10:]),
        'uid-mismatch': b'\x01' + op(0, hello),
        'overflow-own': b'\x02' + op(0, hello),
        'zero-length': b'\x00' + op(0, b'\x00\x00\x00\x00'),
    }


def cmsg(level: int, kind: int, data: bytes) -> bytes:
    header = struct.pack('=QII', 16 + len(data), level, kind)
    pad = (-len(data)) % 8
    return header + data + b'\x00' * pad


def ancillary_seeds() -> dict[str, bytes]:
    cred = cmsg(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('=iII', 4242, 1000, 1000))
    rights = cmsg(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('=i', 7))
    return {
        'credential': b'\x00\x0d' + cred,
        'credential-early': b'\x00\x0f' + cred,
        'rights-one': b'\x00\x00' + rights,
        'rights-two': b'\x00\x00' + cmsg(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('=ii', 7, 8)),
        'credential-and-rights': b'\x00\x0d' + cred + rights,
        'duplicate-credential': b'\x00\x0d' + cred + cred,
        'truncated': b'\x02\x0d' + cred,
        'short-header': b'\x00\x0d' + cred[:12],
        # structured mode (byte 0 bit 7): one byte per well-formed header; the harness builds the buffer
        'structured-one-fd': b'\x80\x00' + bytes([1 << 2]),
        'structured-two-headers': b'\x80\x00' + bytes([2 << 2, 1]),
        'structured-credential': b'\x80\x0d' + bytes([1]),
        'structured-truncated-rights': b'\x82\x00' + bytes([3 << 2]),
        'structured-over-256': b'\x80\x00' + bytes([63 << 2] * 5),
        'structured-other-level': b'\x80\x00' + bytes([1 << 2, 2]),
        'structured-bad-credential': b'\x80\x0d' + bytes([3, 1 << 2]),
    }


def control_seeds() -> dict[str, bytes]:
    common = {'v': 1, 'engine_epoch': EPOCH, 'seq': '1'}
    row = {**common, 'execution_id': EXECUTION, 'lease_id': EXECUTION + ':u'}
    records = {
        'control_ready': {**common, 'type': 'control_ready', 'catalog_digest': DIGEST, 'protocol': 'w2-local/2',
                          'runtime_storage_protocol': 'w2-runtime-store/1', 'storage_profile_digest': DIGEST},
        'spawn': {**row, 'type': 'spawn', 'uid': 1000, 'gid': 1000, 'launch_plan_id': 'plan-1',
                  'launch_plan_digest': DIGEST, 'startup_deadline_ns': '5000000000'},
        'spawn_prepared': {**row, 'type': 'spawn_prepared', 'launch_plan_digest': DIGEST, 'policy_digest': DIGEST,
                           'isolation_profile_digest': DIGEST, 'child_pid': 42, 'sealed': True,
                           'copy_id': EXECUTION + ':r', 'connector_pid': 43, 'worker_pid': 44},
        'connector_exited': {**row, 'type': 'connector_exited', 'exit_code': None, 'signal': 9},
        'worker_exited': {**row, 'type': 'worker_exited', 'exit_code': 0, 'signal': None},       # validation.md H-17
        'runtime_status': {**row, 'type': 'runtime_status', 'copy_id': EXECUTION + ':r', 'state': 'released',
                           'basis': 'tree_removed', 'reason': 'none', 'attempt': 1, 'os_errno': None},
        'spawn_failed': {**row, 'type': 'spawn_failed', 'stage': 'uid', 'error_code': 'os_error', 'os_errno': 1},
        'stop': {**row, 'type': 'stop', 'reason': 'normal'},
        'execution_empty': {**row, 'type': 'execution_empty', 'basis': 'pid1_reaped', 'exit_code': 0,
                            'signal': None, 'last_stage': 'commit'},
    }
    return {name: body(rec) for name, rec in records.items()}


def judge_seeds() -> dict[str, bytes]:
    """Block 4: the judgment-port reader (fuzz_judge.c). Frames are length-prefixed binary (SPEC §2); a JUDGE frame
    carries one descriptor, the memfd of the body."""
    def field(data: bytes) -> bytes:
        return len(data).to_bytes(4, 'big') + data

    def bframe(kind: int, fields: list[bytes]) -> bytes:
        payload = bytes([kind]) + b''.join(field(f) for f in fields)
        return len(payload).to_bytes(4, 'big') + payload

    judge = bframe(0x21, [(1).to_bytes(8, 'big'), (60000).to_bytes(4, 'big'), b'GET', b'https',
                          b'api.test', (443).to_bytes(2, 'big'), b'/', b'', b'\x00\x00\x00\x00', b'\x00\x00\x00\x00', b'',
                          b'\x00\x00\x00\x00', (0).to_bytes(8, 'big')])
    withdraw = bframe(0x22, [(1).to_bytes(8, 'big')])
    report = bframe(0x23, [(1).to_bytes(8, 'big'), b'\x01', (200).to_bytes(2, 'big')])
    return {
        'judge-with-fd': b'\x00' + op(1, judge),
        'judge-no-fd': b'\x00' + op(0, judge),
        'judge-split-fd-first': b'\x00' + op(1, judge[:9]) + op(0, judge[9:]),
        'judge-two-fds': b'\x00' + op(1, judge[:9]) + op(1, judge[9:]),
        'three-frames': b'\x00' + op(0, judge + withdraw + report),
        'header-split': b'\x00' + op(0, judge[:1]) + op(0, judge[1:4]) + op(0, judge[4:20]) + op(0, judge[20:]),
        'oob': b'\x00' + op(0, judge[:10]) + op(2) + op(0, judge[10:]),
        'uid-mismatch': b'\x01' + op(0, judge),
        'overflow-own': b'\x02' + op(0, judge),
        'zero-length': b'\x00' + op(0, b'\x00\x00\x00\x00'),
        'over-cap': b'\x00' + op(0, b'\x00\x10\x00\x01' + b'\x21'),
    }


def main() -> int:
    out = Path(sys.argv[1])
    for entry, seeds in (('frame', frame_seeds()), ('ancillary', ancillary_seeds()), ('control', control_seeds()),
                         ('judge', judge_seeds())):
        directory = out / entry
        directory.mkdir(parents=True, exist_ok=False)
        for name, data in seeds.items():
            (directory / name).write_bytes(data)
    return 0


if __name__ == '__main__':
    sys.exit(main())
