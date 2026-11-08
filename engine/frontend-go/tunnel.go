package main

// CONNECT: the tunnel is answered at once and never connected anywhere (mitmproxy connection_strategy=lazy); what the
// client sends next decides the layer, by the rules of mitmproxy 12.3.1 addons/next_layer.py: bytes that start like a
// TLS record are TLS terminated with the execution's CA; otherwise, with no ALPN to go by, bytes that do not look like
// HTTP close the tunnel (rawtcp → tcp_start → flow.kill, F-02), and anything else is served as HTTP through the
// connector, never passed through.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// A client that has not sent enough to decide the layer within this time is closed.
const decideTimeout = 30 * time.Second

func (f *front) connect(w http.ResponseWriter, r *http.Request) {
	host, port, hasPort, ok := parseAuthority(r.RequestURI)
	if !ok || !hasPort || port == 0 {
		fail(w, http.StatusBadRequest, "bad CONNECT target")
		return
	}
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	if _, err := conn.Write([]byte(r.Proto + " 200 Connection established\r\n\r\n")); err != nil {
		conn.Close()
		return
	}
	f.tunnel(conn, rw.Reader, host, port)
}

func startsLikeTLS(d []byte) bool { // mitmproxy/net/tls.py starts_like_tls_record
	return len(d) > 2 && d[0] == 0x16 && d[1] == 0x03 && d[2] <= 0x03
}

func probablyNoHTTP(d []byte) bool { // next_layer.py step 5d, with no server greeting (lazy: no server connection)
	alpha := len(d) >= 3
	for i := 0; alpha && i < 3; i++ {
		c := d[i] | 0x20
		alpha = c >= 'a' && c <= 'z'
	}
	return len(d) < 3 || !bytes.Contains(d, []byte(" ")) ||
		bytes.IndexByte(d, ' ') > bytes.IndexByte(d, '\n') || !alpha || bytes.HasPrefix(d, []byte("SSH"))
}

// undecided: the bytes so far could still become either layer. Fewer than three bytes are neither a TLS record header
// nor a method yet; three letters and no line end yet are a request line still arriving, its first space or not.
func undecided(d []byte) bool {
	if len(d) < 3 {
		return true
	}
	if startsLikeTLS(d) || bytes.HasPrefix(d, []byte("SSH")) || bytes.IndexByte(d, '\n') >= 0 {
		return false
	}
	for _, c := range d[:3] {
		if l := c | 0x20; l < 'a' || l > 'z' {
			return false
		}
	}
	return true
}

// settle reads until the first bytes decide the layer (TCP may hand a client hello over one byte at a time), up to the
// reader's buffer and decideTimeout; nil when the client went away or sent too little in time.
func settle(conn net.Conn, br *bufio.Reader) []byte {
	conn.SetReadDeadline(time.Now().Add(decideTimeout))
	defer conn.SetReadDeadline(time.Time{})
	for want := 1; ; want = br.Buffered() + 1 {
		if _, err := br.Peek(want); err != nil {
			return nil
		}
		if first, _ := br.Peek(br.Buffered()); !undecided(first) || len(first) >= br.Size() {
			return first
		}
	}
}

// tunnel decides on the first bytes that arrive, as mitmproxy decides on the first data it receives, once there are
// enough of them to decide.
func (f *front) tunnel(conn net.Conn, br *bufio.Reader, host string, port int) {
	scheme, alpn := "http", ""
	for {
		if alpn != "" { // an HTTP ALPN was negotiated: HTTP without looking (next_layer.py step 5a)
			break
		}
		first := settle(conn, br)
		if first == nil {
			conn.Close()
			return
		}
		if startsLikeTLS(first) {
			local, _, _ := net.SplitHostPort(conn.LocalAddr().String())
			tc := tls.Server(&bufConn{conn, br}, f.certs.serverConfig(host, local))
			if err := tc.Handshake(); err != nil {
				conn.Close()
				return
			}
			conn, br, scheme, alpn = tc, bufio.NewReader(tc), "https", tc.ConnectionState().NegotiatedProtocol
			continue
		}
		if probablyNoHTTP(first) {
			conn.Close()
			return
		}
		break
	}
	f.inner.push(&tunnelConn{bufConn{conn, br}, destination{scheme, host, port}})
}

// bufConn reads through the reader that already holds the bytes looked at.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// tunnelConn carries the tunnel's destination into the request context (http.Server.ConnContext).
type tunnelConn struct {
	bufConn
	dest destination
}

// connQueue is a net.Listener whose connections are the tunnels that carry HTTP.
type connQueue struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
	addr net.Addr
}

func newConnQueue(addr net.Addr) *connQueue {
	return &connQueue{ch: make(chan net.Conn), done: make(chan struct{}), addr: addr}
}

func (q *connQueue) push(c net.Conn) {
	select {
	case q.ch <- c:
	case <-q.done:
		c.Close()
	}
}

func (q *connQueue) Accept() (net.Conn, error) {
	select {
	case c := <-q.ch:
		return c, nil
	case <-q.done:
		return nil, net.ErrClosed
	}
}

func (q *connQueue) Close() error {
	q.once.Do(func() { close(q.done) })
	return nil
}

func (q *connQueue) Addr() net.Addr { return q.addr }
