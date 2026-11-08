package main

// Link G, the row's file port (MCP server <-> file worker): the encoding of SPEC-canonical-form.md §2 with the kinds of
// the file-read section. Kept local like frontend-go/wire.go: this program needs nothing from the TCB tree, and the
// worker reads everything sent here as untrusted input.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	kindListObjects = 0x71 // MCP -> worker: no fields
	kindList        = 0x72 // MCP -> worker: alias, path, start(u32)
	kindRead        = 0x73 // MCP -> worker: alias, path, offset(u64), length(u32)
	kindObjects     = 0x74 // worker -> MCP: objects(list of lists: alias, host_path, type(u8), ops(u8), approval(u8))
	kindEntries     = 0x75 // worker -> MCP: more(u8), entries(list: name and type(u8) alternating)
	kindData        = 0x76 // worker -> MCP: total_size(u64), data
	kindRefused     = 0x77 // worker -> MCP: reason(u8)

	requestFrameLimit = 8 << 10 // the worker drops a longer request frame unread
	replyFrameLimit   = 1 << 20 // 128 objects with 4096-byte host paths need about 524 KiB
	readMax           = 256 << 10
	listMax           = 1000
	relPathMax        = 4096
	objectsMax        = 128

	typeFile = 1
	typeDir  = 2
	opRead   = 1 // ops bits
	opList   = 2

	approvalNever  = 1 // allowed without asking (workspaces.Approval.NEVER)
	approvalAlways = 2 // the user is asked every time (workspaces.Approval.ALWAYS)

	// callTimeout outlasts the worker's own wait for the core (330 s, connector/session.py WAIT_TIMEOUT), so a
	// request that waits for the user is answered by the worker, not cut here.
	callTimeout = 345 * time.Second
)

var replyFields = map[byte]int{kindObjects: 1, kindEntries: 2, kindData: 2, kindRefused: 1}

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

func packFrame(kind byte, fields ...[]byte) []byte {
	n := 1
	for _, f := range fields {
		n += 4 + len(f)
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+n), uint32(n))
	out = append(out, kind)
	for _, f := range fields {
		out = appendField(out, f)
	}
	return out
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

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

// unpackList reads a list field: a count, then exactly that many items, at most max of them.
func unpackList(data []byte, max int) ([][]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	count := binary.BigEndian.Uint32(data)
	if uint64(count) > uint64(max) {
		return nil, false
	}
	items, ok := unpack(data[4:])
	if !ok || len(items) != int(count) {
		return nil, false
	}
	return items, true
}

var errMalformed = errors.New("reply does not read")

// readFrame reads one frame of at most limit bytes after the length word; a longer one is refused before its body is
// read.
func readFrame(r io.Reader, limit uint32) (kind byte, fields [][]byte, err error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(head[:])
	if length < 1 || length > limit {
		return 0, nil, fmt.Errorf("frame length %d outside 1..%d", length, limit)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	fields, ok := unpack(body[1:])
	if !ok {
		return 0, nil, errMalformed
	}
	return body[0], fields, nil
}

// refused is the worker's FILE_REFUSED: the core's (or the worker's) reason, passed on to the agent as its word.
type refused struct{ code byte }

func (e refused) Error() string { return reasonWord(e.code) }

// portConn is one connection to the file socket: one tool call, its requests in turn, each answered before the next.
type portConn struct{ c net.Conn }

func dialPort(ctx context.Context, path string) (*portConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(callTimeout))
	context.AfterFunc(ctx, func() { c.Close() }) // the agent went away: the worker sees the file port close
	return &portConn{c: c}, nil
}

func (p *portConn) Close() error { return p.c.Close() }

// exchange sends one request and returns the fields of its reply; a FILE_REFUSED comes back as a refused error.
func (p *portConn) exchange(frame []byte, want byte) ([][]byte, error) {
	if _, err := p.c.Write(frame); err != nil {
		return nil, err
	}
	kind, fields, err := readFrame(p.c, replyFrameLimit)
	if err != nil {
		return nil, err
	}
	if (kind != want && kind != kindRefused) || len(fields) != replyFields[kind] {
		return nil, fmt.Errorf("%w: kind %#x with %d fields", errMalformed, kind, len(fields))
	}
	if kind == kindRefused {
		if len(fields[0]) != 1 {
			return nil, errMalformed
		}
		return nil, refused{fields[0][0]}
	}
	return fields, nil
}

type hostObject struct {
	alias    string
	hostPath string
	isDir    bool
	ops      byte
	approval byte
}

func (p *portConn) listObjects() ([]hostObject, error) {
	fields, err := p.exchange(packFrame(kindListObjects), kindObjects)
	if err != nil {
		return nil, err
	}
	items, ok := unpackList(fields[0], objectsMax)
	if !ok {
		return nil, errMalformed
	}
	objects := make([]hostObject, 0, len(items))
	for _, item := range items {
		f, ok := unpackList(item, 5)
		if !ok || len(f) != 5 || len(f[2]) != 1 || len(f[3]) != 1 || len(f[4]) != 1 ||
			(f[2][0] != typeFile && f[2][0] != typeDir) {
			return nil, errMalformed
		}
		objects = append(objects, hostObject{alias: string(f[0]), hostPath: string(f[1]), isDir: f[2][0] == typeDir,
			ops: f[3][0], approval: f[4][0]})
	}
	return objects, nil
}

type dirEntry struct {
	name []byte
	kind byte // 0 unknown, 1 regular file, 2 directory, 3 symbolic link, 4 other
}

func (p *portConn) list(alias, rel string, start uint32) (more bool, entries []dirEntry, err error) {
	fields, err := p.exchange(packFrame(kindList, []byte(alias), []byte(rel), u32(start)), kindEntries)
	if err != nil {
		return false, nil, err
	}
	items, ok := unpackList(fields[1], 2*listMax)
	if !ok || len(fields[0]) != 1 || fields[0][0] > 1 || len(items)%2 != 0 {
		return false, nil, errMalformed
	}
	for i := 0; i < len(items); i += 2 {
		if len(items[i+1]) != 1 {
			return false, nil, errMalformed
		}
		entries = append(entries, dirEntry{name: items[i], kind: items[i+1][0]})
	}
	return fields[0][0] == 1, entries, nil
}

func (p *portConn) read(alias, rel string, offset uint64, length uint32) (total uint64, data []byte, err error) {
	fields, err := p.exchange(packFrame(kindRead, []byte(alias), []byte(rel), u64(offset), u32(length)), kindData)
	if err != nil {
		return 0, nil, err
	}
	if len(fields[0]) != 8 || len(fields[1]) > readMax {
		return 0, nil, errMalformed
	}
	return binary.BigEndian.Uint64(fields[0]), fields[1], nil
}
