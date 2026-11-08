"""这是 2.3 凭据使用绑定的验证测试：只对本次运行自建的账户、哨兵凭据与断网测试上游，检查真值是否被取出、放错位置或发往未授权的目的地；不使用真实账户或真实凭据。"""
# Cold-audit finding 1 (2026-11-04): the engine row's terminal stream is a declared
# trace outlet; it is captured from before the cell's gate to relay EOF, or a gap.
import os
import time
import unittest
import unittest.mock
from types import SimpleNamespace
import test_cb_collect as collect_tests

GATE = 'nb-decoy-terminal-' + 'a' * 48
RELAY = b'attached to x; Ctrl-] detaches\n\r\nthe relay closed the connection (the row ended, or another client is attached)\n'


def stream(stdout, stderr=RELAY, code=0):
    child = SimpleNamespace(proc=SimpleNamespace(poll=lambda: code), streams=0,
                            buffers={'stdout': bytearray(stdout), 'stderr': bytearray(stderr)})
    return SimpleNamespace(child=child, closed=False, command=SimpleNamespace(close_input=lambda c: None))


RT = SimpleNamespace(command=SimpleNamespace(deadline=SimpleNamespace(left=lambda t: t), pump=lambda s: None))


class Finish(unittest.TestCase):
    def finish(self, s, **k):
        from cb_terminal import finish_terminal
        return finish_terminal(RT, s, GATE, **k)

    def test_relay_eof_with_gate_echo_first_is_complete(self):
        r = self.finish(stream((GATE + '\r\nchild said hi\r\n').encode()))
        self.assertTrue(r['complete'], r['reason']);self.assertIn(b'child said hi', r['data'])

    def test_other_endings_and_missing_echo_are_gaps(self):
        cases = {'input-eof': stream((GATE + '\r\n').encode(), stderr=b'attached\n\r\nend of input\n'),
                 'exit': stream((GATE + '\r\n').encode(), code=1),
                 'pre-gate-bytes': stream(('early\r\n' + GATE + '\r\n').encode()),
                 'no-echo': stream(b'')}
        for name, s in cases.items():
            with self.subTest(name=name):
                self.assertFalse(self.finish(s)['complete'])

    def test_client_that_never_ends_is_a_gap_not_a_hang(self):
        s = stream((GATE + '\r\n').encode(), code=None)
        r = self.finish(s, timeout=0.05)
        self.assertFalse(r['complete']);self.assertIn('did not end', r['reason'])


class Outlet(unittest.TestCase):
    def setUp(self):
        self.c = collect_tests.Collect('test_every_declared_outlet_is_inventoried_and_quiet_collector_is_not_produced')
        self.c.setUp()

    def tearDown(self):
        self.c.tearDown()

    def test_engine_row_without_terminal_capture_is_incomplete(self):
        r = self.c.collect(terminal=None)
        self.assertFalse(r['complete']);self.assertIn('trace:engine row terminal not captured', r['gaps'])

    def test_truth_on_the_terminal_is_a_forbidden_trace_hit(self):
        data = (GATE + '\r\n').encode() + self.c.accounts[2].truth
        r = self.c.collect(terminal={'data': data, 'complete': True, 'reason': '', 'provenance': {}})
        self.assertIn('trace', {h['outlet'] for h in r['forbidden']})
        self.assertEqual({i['source'].split('.')[-1] for i in r['items'] if i['outlet'] == 'trace'},
                         {'runner-observation', 'runner-terminal'})

    def test_judge_receives_this_attempts_e09_and_connector_stderr(self):
        # Live self-check 2026-11-04: the E-09 suffix variable was overwritten by the core-buffer loop.
        self.c.e09.write_bytes(b'{"n":1}\n{"kind":"request_decided","n":2}\n')
        self.c.engine.buffers['stderr'].extend(b'core says hi')
        self.c.connector['logs']['stderr'] = {'data': b'{"reason":"x"}\n', 'complete': True}
        from cb_outlets import collect
        captured = {}
        original = collect
        def spy(rt, prepared, *a, **k):
            result = original(rt, prepared, *a, **k);captured.update(prepared.get('diagnostics') or {})
            return result
        import cb_outlets
        with unittest.mock.patch.object(cb_outlets, 'collect', spy):
            self.c.collect()
        self.assertEqual(captured, {'e09': b'{"kind":"request_decided","n":2}\n', 'connector': b'{"reason":"x"}\n'})

    def test_incomplete_terminal_capture_is_a_named_gap(self):
        r = self.c.collect(terminal={'data': b'', 'complete': False, 'reason': 'gate echo absent at capture start',
                                     'provenance': {}})
        self.assertIn('trace:gate echo absent at capture start', r['gaps'])


class Order(unittest.TestCase):
    def test_gate_is_frozen_attach_precedes_wait_and_eof_read_follows_tree(self):
        result, events, rt, prepared = collect_tests.RowDriver.drive(self, seen=b'{"prior":1}\n')
        opened = next(e for e in events if isinstance(e, tuple) and e[0] == 'terminal-open')
        self.assertEqual(opened[1], prepared['parameters']['terminal'])
        self.assertEqual(prepared['request']['parameters']['terminal'], opened[1])
        self.assertTrue(opened[1].startswith('nb-decoy-terminal-'))
        self.assertLess(events.index('start'), events.index(opened))
        self.assertLess(events.index('terminal-finish'), events.index(('outlets', True)))
        # The batch's verified E-09 prefix is the next row's required prior (finding 4).
        self.assertIn(('e09', b'{"prior":1}\n'), events)


class CellGate(unittest.TestCase):
    def gate(self, config, params, data=b''):
        from cb_handshake import terminal_gate
        ctx = SimpleNamespace(request={'config': config, 'parameters': params}, clock=time.monotonic,
                              remaining=lambda n=30: min(n, 1))
        r, w = os.pipe();saved = os.dup(0)
        try:
            os.write(w, data);os.close(w);os.dup2(r, 0)
            return terminal_gate(ctx), params
        finally:
            os.dup2(saved, 0);os.close(saved);os.close(r)

    def test_engine_waits_for_exact_gate_line(self):
        _, params = self.gate('engine', {'terminal': GATE, 'x': 1}, (GATE + '\n').encode())
        self.assertEqual(params, {'x': 1})
        for data, error in (((GATE + 'x\n').encode(), ValueError), (b'', ConnectionError)):
            with self.subTest(data=data), self.assertRaises(error):
                self.gate('engine', {'terminal': GATE}, data)

    def test_gate_belongs_to_engine_rows_only(self):
        with self.assertRaises(ValueError):self.gate('engine', {})
        with self.assertRaises(ValueError):self.gate('undefended', {'terminal': GATE})
        self.assertEqual(self.gate('undefended', {'x': 1})[1], {'x': 1})


class Handshake(unittest.TestCase):
    def test_release_seen_mid_publication_is_retried_not_fatal(self):
        # cbfix-b4 (2026-11-04): the host's hard-link publication has a two-link window.
        import json
        from cb_handshake import handshake
        from nb_io import PublicationPending
        written, reads = {}, []
        def read(name, limit):
            reads.append(name)
            if len(reads) == 1:raise FileNotFoundError(name)
            if len(reads) == 2:raise PublicationPending('single-link publication pending')
            return written['ready']
        files = SimpleNamespace(write=lambda name, data: written.__setitem__('ready', data), read=read)
        ctx = SimpleNamespace(request={'config': 'undefended', 'parameters': {'measurement': {
            'ready': 'nb-decoy-ready', 'release': 'nb-decoy-release', 'marker': 'm'}}},
            files=files, clock=time.monotonic, sleep=lambda s: None, remaining=lambda n=30: min(n, 2))
        handshake(ctx)
        self.assertEqual(len(reads), 3);self.assertEqual(json.loads(written['ready'])['marker'], 'm')


if __name__ == '__main__':
    unittest.main()
