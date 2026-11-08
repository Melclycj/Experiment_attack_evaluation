"""这是 3.1 判定忠实的验证测试：只对本次运行自建的条目、账户、测试凭据与断网测试上游，检查 engine 是否忠实执行已作出的判定；不使用真实账户或真实凭据。

The runner's canonical-form encoder against the pinned connector's own parser, and both response readers on socket
pairs.
"""
from __future__ import annotations

import socket
import threading

import df_wire as w


def test_request_frame_parses_in_the_pinned_connector(canonical):
    req = {"method": "POST", "scheme": "https", "host": "nb-decoy-up", "port": 443, "path": "/ok",
           "query": "n=0123456789abcdef-a", "headers": [("authorization", "Bearer nb-decoy-placeholder"),
                                                       ("content-type", "application/json")], "body": b'{"x":1}'}
    frame = w.request_frame(req)
    parser = canonical.FrameParser(canonical.LIMITS.frame_a, canonical.LINK_A_IN)
    frames = list(parser.feed(frame))
    assert len(frames) == 1 and frames[0][0] == canonical.REQUEST
    parsed = canonical.parse_request(frames[0][1])
    assert parsed.method == b"POST" and parsed.host == b"nb-decoy-up" and parsed.port == 443
    assert parsed.path == b"/ok" and parsed.query == b"n=0123456789abcdef-a"
    assert (b"authorization", b"Bearer nb-decoy-placeholder") in parsed.headers
    assert parsed.body == b'{"x":1}' and parsed.body_kind == "application/json"


def test_ip_literal_request_is_marked_ip(canonical):
    req = {"method": "GET", "scheme": "http", "host": "10.66.0.10", "port": 80, "path": "/", "query": None,
           "headers": [], "body": b""}
    parser = canonical.FrameParser(canonical.LIMITS.frame_a, canonical.LINK_A_IN)
    parsed = canonical.parse_request(list(parser.feed(w.request_frame(req)))[0][1])
    assert parsed.is_ip and parsed.query is None


def test_proxy_events_from_pinned_frames(canonical):
    a, b = socket.socketpair()
    conn = w.ProxyConn.__new__(w.ProxyConn)
    conn.sock, conn.buf, conn.address = a, b"", None
    head = canonical.pack_frame(canonical.RESP_HEAD, [canonical.u8(2), canonical.u16(0),
                                                      canonical.pack_list([b"x-engine-reason", b"not_authorized"])])
    b.sendall(head + canonical.pack_frame(canonical.RESP_CHUNK, [b"refused"]) +
              canonical.pack_frame(canonical.RESP_END, []))
    out = w.collect(conn, 2)
    assert out["category"] == "refused" and out["reason"] == "not_authorized" and out["ended"]
    assert out["body"] == b"refused"
    b.sendall(canonical.pack_frame(canonical.RESP_HEAD, [canonical.u8(1), canonical.u16(200), canonical.pack_list([])])
              + canonical.pack_frame(canonical.RESP_CHUNK, [b"one"]))
    first = w.collect(conn, 2, first_chunk_only=True)
    assert first["chunks"] == 1
    b.close()                                          # cut without RESP_END
    w.collect(conn, 2, into=first)
    assert first["closed"] and not first["ended"]


def direct_pair():
    a, b = socket.socketpair()
    conn = w.DirectConn.__new__(w.DirectConn)
    conn.sock, conn.buf, conn.state, conn.address = a, b"", None, None
    return conn, b


def test_direct_content_length_and_keepalive():
    conn, peer = direct_pair()
    req = {"method": "GET", "scheme": "https", "host": "nb-decoy-up", "port": 443, "path": "/ok", "query": "n=x",
           "headers": [], "body": b""}
    got = []
    t = threading.Thread(target=lambda: got.append(peer.recv(4096)))
    t.start()
    conn.send(req)
    t.join(2)
    assert got[0].startswith(b"GET /ok?n=x HTTP/1.1\r\nhost: nb-decoy-up\r\n")
    peer.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nok\n")
    out = w.collect(conn, 2)
    assert out["status"] == 200 and out["body"] == b"ok\n" and out["ended"]


def test_direct_chunked_and_drop():
    conn, peer = direct_pair()
    conn.state = ("head",)
    peer.sendall(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nab\ncd\r\n0\r\n\r\n")
    out = w.collect(conn, 2)
    assert out["body"] == b"ab\ncd" and out["ended"]
    conn.state = ("head",)
    peer.close()
    dropped = w.collect(conn, 2)
    assert dropped["closed"] and dropped["category"] is None
