package main

// A stand-in for the row's file worker: a unix socket server that reads link G requests (with the worker's 8 KiB
// request cap), records them, and answers what the test's handler returns.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeReq struct {
	kind   byte
	fields [][]byte
	size   int // frame bytes after the length word
}

type fakePort struct {
	path   string
	mu     sync.Mutex
	reqs   []fakeReq
	handle func(r fakeReq) []byte // the raw reply; nil closes the connection without one
}

func newFakePort(t *testing.T, handle func(r fakeReq) []byte) *fakePort {
	t.Helper()
	dir, err := os.MkdirTemp("", "mcp") // short: a unix socket path is at most 107 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakePort{path: filepath.Join(dir, "file.sock"), handle: handle}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePort) serve(c net.Conn) {
	defer c.Close()
	for {
		kind, fields, err := readFrame(c, requestFrameLimit)
		if err != nil {
			return
		}
		size := 1
		for _, x := range fields {
			size += 4 + len(x)
		}
		r := fakeReq{kind: kind, fields: fields, size: size}
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.mu.Unlock()
		reply := f.handle(r)
		if reply == nil {
			return
		}
		if _, err := c.Write(reply); err != nil {
			return
		}
	}
}

func (f *fakePort) kinds() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	for _, r := range f.reqs {
		out = append(out, r.kind)
	}
	return out
}

func (f *fakePort) last() fakeReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

// ---- replies ----

func objectsReply(objs ...hostObject) []byte {
	items := make([][]byte, 0, len(objs))
	for _, o := range objs {
		t := byte(typeFile)
		if o.isDir {
			t = typeDir
		}
		items = append(items, packList([][]byte{[]byte(o.alias), []byte(o.hostPath), {t}, {o.ops}, {o.approval}}))
	}
	return packFrame(kindObjects, packList(items))
}

func entriesReply(more bool, entries ...dirEntry) []byte {
	var items [][]byte
	for _, e := range entries {
		items = append(items, e.name, []byte{e.kind})
	}
	m := byte(0)
	if more {
		m = 1
	}
	return packFrame(kindEntries, []byte{m}, packList(items))
}

func dataReply(total uint64, data []byte) []byte { return packFrame(kindData, u64(total), data) }

func refusedReply(code byte) []byte { return packFrame(kindRefused, []byte{code}) }

func dirObj(alias, path string) hostObject {
	return hostObject{alias: alias, hostPath: path, isDir: true, ops: opRead | opList, approval: approvalNever}
}

func fileObj(alias, path string) hostObject {
	return hostObject{alias: alias, hostPath: path, ops: opRead, approval: approvalNever}
}

// worker answers FILE_LIST_OBJECTS with objs and passes the operation request to op.
func worker(op func(r fakeReq) []byte, objs ...hostObject) func(r fakeReq) []byte {
	return func(r fakeReq) []byte {
		if r.kind == kindListObjects {
			return objectsReply(objs...)
		}
		return op(r)
	}
}

func readFields(r fakeReq) (alias, rel string, offset uint64, length uint32) {
	return string(r.fields[0]), string(r.fields[1]), binary.BigEndian.Uint64(r.fields[2]),
		binary.BigEndian.Uint32(r.fields[3])
}

// ---- the MCP side ----

func post(t *testing.T, s http.Handler, body string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func doRequest(s http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

type rpcReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func decodeReply(t *testing.T, rec *httptest.ResponseRecorder) rpcReply {
	t.Helper()
	var r rpcReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("reply %q does not read: %v", rec.Body.String(), err)
	}
	return r
}

func call(t *testing.T, s http.Handler, tool string, args any) toolResult {
	t.Helper()
	a, _ := json.Marshal(args)
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + string(a) + `}}`
	rec := post(t, s, body, "Mcp-Protocol-Version", protocolVersion)
	if rec.Code != http.StatusOK {
		t.Fatalf("tools/call %s: HTTP %d %s", tool, rec.Code, rec.Body.String())
	}
	r := decodeReply(t, rec)
	if r.Error != nil {
		t.Fatalf("tools/call %s: JSON-RPC error %+v", tool, *r.Error)
	}
	var res toolResult
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

func testServer(f *fakePort) *server { return newServer(f.path, 3129) }

func equalKinds(got []byte, want ...byte) bool { return bytes.Equal(got, want) }
