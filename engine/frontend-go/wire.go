package main

// Link A of SPEC-canonical-form.md §2 and §3.1, kept local like the Python frontend's copy: the frontend needs nothing
// from the TCB tree.

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const (
	kindRequest   = 0x01
	kindRespHead  = 0x11
	kindRespChunk = 0x12
	kindRespEnd   = 0x13

	catRemote  = 1
	catRefused = 2 // 3 transport error and 4 result unknown both become 502, as does any other value

	frameLimit = 64<<20 + 128<<10
	bodyLimit  = 64 << 20
)

func appendField(out, field []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
	return append(out, field...)
}

func packList(items [][]byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
	for _, item := range items {
		out = appendField(out, item)
	}
	return out
}

// writeRequest sends one REQUEST frame: fields then the body as the last field, in one writev so the body is not copied.
func writeRequest(w io.Writer, fields [][]byte, body []byte) error {
	n := 1 + 4 + len(body)
	for _, f := range fields {
		n += 4 + len(f)
	}
	head := binary.BigEndian.AppendUint32(make([]byte, 0, 64), uint32(n))
	head = append(head, kindRequest)
	for _, f := range fields {
		head = appendField(head, f)
	}
	head = binary.BigEndian.AppendUint32(head, uint32(len(body)))
	bufs := net.Buffers{head, body}
	_, err := bufs.WriteTo(w)
	return err
}

// unpack splits data into length-prefixed items; ok is false when a length runs past the end.
func unpack(data []byte) (items [][]byte, ok bool) {
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(data)
		if uint64(n) > uint64(len(data)-4) {
			return nil, false
		}
		items = append(items, data[4:4+n])
		data = data[4+n:]
	}
	return items, true
}

func unpackList(data []byte) ([][]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	items, ok := unpack(data[4:])
	if !ok || uint32(len(items)) != binary.BigEndian.Uint32(data) {
		return nil, false
	}
	return items, true
}

// readFrame returns the next frame; ok is false at EOF, on a read error, on a length outside 1..frameLimit, or when
// the fields do not read (the Python frontend treats the first three the same way: the exchange ends there).
func readFrame(r io.Reader) (kind byte, fields [][]byte, ok bool) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, false
	}
	length := binary.BigEndian.Uint32(head[:])
	if length < 1 || length > frameLimit {
		return 0, nil, false
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, false
	}
	fields, ok = unpack(body[1:])
	return body[0], fields, ok
}

// proxyPath holds connections to the row's proxy path, one per in-flight request, kept for reuse after a complete
// response (the connector keeps its upstream connections per accepted fd, so reusing ours keeps upstream keep-alive).
type proxyPath struct {
	path string
	mu   sync.Mutex
	idle []net.Conn
}

func (p *proxyPath) take() (net.Conn, error) {
	p.mu.Lock()
	if n := len(p.idle); n > 0 {
		c := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	return net.Dial("unix", p.path)
}

func (p *proxyPath) giveBack(c net.Conn) {
	p.mu.Lock()
	p.idle = append(p.idle, c)
	p.mu.Unlock()
}
