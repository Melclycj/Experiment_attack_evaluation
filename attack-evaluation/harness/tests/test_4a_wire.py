"""这是 1.1 隔离论证的验证测试：对本机上、由本次运行从固定版本编出的沙箱，确认越权的尝试被挡住；目标是本次运行自建的诱饵；不研究、也不记录任何绕过方法。"""
import importlib
import os
import struct
import sys
import unittest
from unittest.mock import Mock, patch
from nb_wire import frame, request_bytes, response, exchange, open_request
from deploy_fixtures import ENGINE_SOURCE


class Stream:
    def __init__(self,data): self.data=data; self.closed=False
    def recv(self,n):
        out,self.data=self.data[:min(n,3)],self.data[min(n,3):]
        return out
    def settimeout(self,n): pass
    def connect(self,path): self.path=path
    def sendall(self,data): self.sent=data
    def close(self): self.closed=True
    def __enter__(self): return self
    def __exit__(self,*_): self.close()


def reply(body=b'{"token":"fresh"}'):
    return frame(0x11,[b'\x01',struct.pack('>H',200),struct.pack('>I',0)])+frame(0x12,[body])+frame(0x13,[])


class WireTests(unittest.TestCase):
    def setUp(self):
        for name, value in [('AF_UNIX', 1), ('SO_PEERCRED', 17)]:
            guard = patch('socket.' + name, value, create=True)
            guard.start(); self.addCleanup(guard.stop)

    def test_partial_response_reassembles_through_end(self):
        got=response(Stream(reply()),lambda:1)
        self.assertEqual(got,{'category':1,'status':200,'body':b'{"token":"fresh"}','complete':True})

    def test_refusal_is_not_a_success_assertion(self):
        data=frame(0x11,[b'\x02',b'\0\0',b'\0'*4])+frame(0x13,[])
        self.assertEqual(response(Stream(data),lambda:1)['category'],2)

    def test_truncated_or_reordered_response_fails(self):
        for data in (reply()[:-1],frame(0x13,[]),frame(0x12,[b'x']),frame(0x51,[]),
                     struct.pack('>I',65537),frame(0x11,[b'\1',b'\0\xc8',b'bad']),
                     reply()[:len(frame(0x11,[b'\1',b'\0\xc8',b'\0'*4]))]*2):
            with self.subTest(data=data[:8]),self.assertRaises((ValueError,ConnectionError)):
                response(Stream(data),lambda:1)

    def test_timeout_propagates_without_body_success(self):
        conn=Mock(); conn.recv.side_effect=TimeoutError('offline')
        with self.assertRaises(TimeoutError): response(conn,lambda:1)

    def test_socket_cleanup_on_connect_failure(self):
        conn=Mock(); conn.connect.side_effect=OSError('offline refusal')
        with patch('nb_wire.socket.socket',return_value=conn), self.assertRaises(OSError):
            open_request('GET','nb-decoy-upstream.test','/nb-decoy-x',lambda:1)
        conn.close.assert_called_once()

    def test_get_uses_fixed_proxy_not_environment(self):
        conn=Stream(reply())
        with patch('nb_wire.socket.socket',return_value=conn):
            exchange('GET','nb-decoy-upstream.test','/nb-decoy-x',lambda:1)
        self.assertEqual(conn.path,'/run/w2/proxy.sock'); self.assertTrue(conn.closed)
        self.assertEqual(conn.sent,request_bytes('GET','nb-decoy-upstream.test','/nb-decoy-x'))

    def test_foreign_host_and_arbitrary_path_refused(self):
        for method,host,path in [('GET','example.com','/nb-decoy-x'),('DELETE','nb-decoy-upstream.test','/nb-decoy-x'),
                                  ('GET','nb-decoy-upstream.test','/../../etc/passwd')]:
            with self.assertRaises(ValueError): request_bytes(method,host,path)

    @unittest.skipUnless(os.name=='posix','production canonical imports fcntl; no network I/O')
    def test_generated_request_decodes_with_current_production_parser(self):
        sys.path.insert(0,str(ENGINE_SOURCE))
        try: c=importlib.import_module('connector.canonical')
        finally: sys.path.pop(0)
        for method,host in [('GET','nb-decoy-upstream.test'),('POST','nb-decoy-question.test')]:
            wire=request_bytes(method,host,'/nb-decoy-fixture')
            kind, fields=c.FrameParser(c.LIMITS.frame_a,c.LINK_A_IN).feed(wire)[0]
            parsed=c.parse_request(fields)
            self.assertEqual(kind,c.REQUEST); self.assertEqual(parsed.path,b'/nb-decoy-fixture')
            self.assertEqual(c.encode_request(parsed),wire)
