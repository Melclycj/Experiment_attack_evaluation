package main

// The transport and the protocol: initialize and the version, the probe of the newer protocol, notifications, GET and
// DELETE, Origin, malformed messages, and the program itself from argv to a served initialize.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func noPort(t *testing.T) *server {
	return testServer(newFakePort(t, func(fakeReq) []byte { t.Error("the file port was contacted"); return nil }))
}

func TestInitializeAnswersTheOneVersion(t *testing.T) {
	s := noPort(t)
	for _, offered := range []string{"2025-11-25", "2026-07-28", "2024-11-05", ""} {
		params := `{"protocolVersion":"` + offered + `","capabilities":{},"clientInfo":{"name":"claude-code","version":"2.1.312"}}`
		rec := post(t, s, `{"jsonrpc":"2.0","id":0,"method":"initialize","params":`+params+`}`)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("offered %q: HTTP %d, %q", offered, rec.Code, rec.Header().Get("Content-Type"))
		}
		r := decodeReply(t, rec)
		var res struct {
			ProtocolVersion string                     `json:"protocolVersion"`
			Capabilities    map[string]json.RawMessage `json:"capabilities"`
			ServerInfo      map[string]string          `json:"serverInfo"`
		}
		if err := json.Unmarshal(r.Result, &res); err != nil || string(r.ID) != "0" || r.JSONRPC != "2.0" {
			t.Fatalf("offered %q: %s", offered, rec.Body.String())
		}
		if res.ProtocolVersion != "2025-11-25" || res.Capabilities["tools"] == nil || len(res.Capabilities) != 1 ||
			res.ServerInfo["name"] != "engine-mcp" {
			t.Errorf("offered %q: %+v", offered, res)
		}
		if rec.Header().Get("Mcp-Session-Id") != "" {
			t.Error("a session id was issued")
		}
	}
	// a string id comes back as the same string
	r := decodeReply(t, post(t, s, `{"jsonrpc":"2.0","id":"a-1","method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	if string(r.ID) != `"a-1"` {
		t.Errorf("id %s", r.ID)
	}
}

// Claude Code's first POST probes the newer protocol; the classic server answers 400 and the client initializes
// (checks/gate_items.py j_mcp).
func TestProbeOfTheNewerProtocolIs400(t *testing.T) {
	s := noPort(t)
	probe := `{"jsonrpc":"2.0","id":0,"method":"server/discover","params":{}}`
	rec := post(t, s, probe, "Mcp-Method", "server/discover", "Mcp-Protocol-Version", "2026-07-28")
	r := decodeReply(t, rec)
	if rec.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != -32000 || string(r.ID) != "null" ||
		!strings.Contains(r.Error.Message, "2025-11-25") {
		t.Fatalf("probe: HTTP %d %s", rec.Code, rec.Body.String())
	}
	// the negotiated version in the header is fine; without a header the method is simply unknown
	for _, h := range [][]string{{"Mcp-Protocol-Version", "2025-11-25"}, nil} {
		rec = post(t, s, probe, h...)
		if r := decodeReply(t, rec); rec.Code != http.StatusOK || r.Error == nil || r.Error.Code != -32601 {
			t.Errorf("header %v: HTTP %d %s", h, rec.Code, rec.Body.String())
		}
	}
}

func TestNotificationsAndResponsesAre202(t *testing.T) {
	s := noPort(t)
	for _, body := range []string{
		`{"method":"notifications/initialized","jsonrpc":"2.0"}`,
		`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`,
		`{"jsonrpc":"2.0","id":5,"result":{}}`,
	} {
		rec := post(t, s, body, "Mcp-Protocol-Version", "2025-11-25")
		if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
			t.Errorf("%s: HTTP %d %q", body, rec.Code, rec.Body.String())
		}
	}
}

func TestPing(t *testing.T) {
	rec := post(t, noPort(t), `{"jsonrpc":"2.0","id":9,"method":"ping"}`)
	if r := decodeReply(t, rec); rec.Code != http.StatusOK || string(r.Result) != "{}" || string(r.ID) != "9" {
		t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
	}
}

func TestGetAndDeleteAre405(t *testing.T) {
	s := noPort(t)
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		rec := doRequest(s, m, "/mcp", "")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
			t.Errorf("%s: HTTP %d Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if rec := doRequest(s, http.MethodPost, "/other", "{}"); rec.Code != http.StatusNotFound {
		t.Errorf("other path: HTTP %d", rec.Code)
	}
}

func TestOrigin(t *testing.T) {
	s := noPort(t)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for origin, want := range map[string]int{
		"http://127.0.0.1:3129": http.StatusOK, "http://localhost:3129": http.StatusOK,
		"http://evil.example": http.StatusForbidden, "http://127.0.0.1:3128": http.StatusForbidden, "null": http.StatusForbidden,
	} {
		if rec := post(t, s, ping, "Origin", origin); rec.Code != want {
			t.Errorf("Origin %q: HTTP %d, want %d", origin, rec.Code, want)
		}
	}
	if rec := post(t, s, ping); rec.Code != http.StatusOK {
		t.Errorf("no Origin: HTTP %d", rec.Code)
	}
}

func TestMalformedMessages(t *testing.T) {
	s := noPort(t)
	for body, code := range map[string]int{
		`not json`: -32600, `{"jsonrpc":"2.0","id":1,"method":`: -32700,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`: -32600, `{"jsonrpc":"1.0","id":1,"method":"ping"}`: -32600,
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`: -32600, `{"jsonrpc":"2.0","id":{},"method":"ping"}`: -32600,
		`{"jsonrpc":"2.0","id":1}`: -32600, ``: -32600,
	} {
		rec := post(t, s, body)
		if r := decodeReply(t, rec); rec.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != code {
			t.Errorf("%q: HTTP %d %s", body, rec.Code, rec.Body.String())
		}
	}
	rec := post(t, s, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	if r := decodeReply(t, rec); rec.Code != http.StatusOK || r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("unknown method: %s", rec.Body.String())
	}
	rec = post(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_host_file","arguments":{}}}`)
	if r := decodeReply(t, rec); r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("unknown tool: %s", rec.Body.String())
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", bodyLimit) + `"}}`
	if rec := post(t, s, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("body over 1 MiB: HTTP %d", rec.Code)
	}
}

// The program: bad argv, then a real listener that says ready only once it accepts, and serves initialize.
func TestRunListensThenSaysReady(t *testing.T) {
	for _, argv := range [][]string{nil, {"a", "b"}, {"/s", "0", "/r"}, {"/s", "65536", "/r"}, {"/s", "x", "/r"}} {
		if code := run(argv); code != 2 {
			t.Errorf("%v: exit %d", argv, code)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	go run([]string{filepath.Join(dir, "file.sock"), fmt.Sprint(port), ready})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no ready file")
		}
		time.Sleep(10 * time.Millisecond)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	resp, err := http.Post(url, "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r rpcReply
	if json.NewDecoder(resp.Body).Decode(&r) != nil || resp.StatusCode != http.StatusOK || r.Result == nil {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	// the port is taken now: a second server fails before saying ready, and leaves no ready file
	ready2 := filepath.Join(dir, "ready2")
	if code := run([]string{filepath.Join(dir, "file.sock"), fmt.Sprint(port), ready2}); code != 1 {
		t.Errorf("second listener: exit %d", code)
	}
	if _, err := os.Stat(ready2); err == nil {
		t.Error("ready file written without a listener")
	}
}
