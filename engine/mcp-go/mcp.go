package main

// MCP over the Streamable HTTP transport, the stateless subset: one endpoint, /mcp; each POST carries one JSON-RPC
// message and a request is answered with one application/json body (no SSE, no Mcp-Session-Id); GET (the server
// notification stream) and DELETE (session end) are 405, which the transport allows.
//
// Protocol version: Claude Code 2.1.312 first probes a newer protocol with a POST carrying mcp-method and
// mcp-protocol-version 2026-07-28; a server that answers it 400 gets the classic initialize, and the session then runs
// on 2025-11-25 (checks/gate_items.py j_mcp; the request headers in runs/20261102T150821Z-gate-rework). So this server
// speaks 2025-11-25 only: initialize gets that version back whatever the client offered, and a request whose
// MCP-Protocol-Version header names another version is answered 400, as the transport requires.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

const (
	protocolVersion = "2025-11-25"
	bodyLimit       = 1 << 20
	serverVersion   = "1.0.0"
	instructions    = "Read-only access to host files and directories the user registered for this workspace, by " +
		"absolute host path. Call list_host_objects first to see what is registered."
)

type server struct {
	socket  string          // the row's file port inside the cell
	origins map[string]bool // Origin values accepted besides none (DNS rebinding guard of the transport)
}

func newServer(socket string, port int) *server {
	return &server{socket: socket, origins: map[string]bool{
		fmt.Sprintf("http://127.0.0.1:%d", port): true, fmt.Sprintf("http://localhost:%d", port): true}}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  *string         `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// badRequest is an HTTP 400 with a JSON-RPC error that answers no request (id null).
func badRequest(w http.ResponseWriter, code int, text string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"jsonrpc": "2.0", "id": nil,
		"error": rpcError{Code: code, Message: text}})
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		http.NotFound(w, r)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !s.origins[o] {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "this server has no notification stream and no session", http.StatusMethodNotAllowed)
		return
	}
	if v := r.Header.Get("Mcp-Protocol-Version"); v != "" && v != protocolVersion {
		badRequest(w, -32000, fmt.Sprintf("Bad Request: Unsupported protocol version: %s (supported versions: %s)",
			v, protocolVersion))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		http.Error(w, "body over 1 MiB", http.StatusRequestEntityTooLarge)
		return
	} else if err != nil {
		badRequest(w, -32700, "Parse error: the body did not arrive")
		return
	}
	var msg message
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' {
		badRequest(w, -32600, "Invalid Request: one JSON-RPC object per POST (no batches)")
		return
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		badRequest(w, -32700, "Parse error")
		return
	}
	if msg.JSONRPC != "2.0" {
		badRequest(w, -32600, `Invalid Request: jsonrpc must be "2.0"`)
		return
	}
	switch {
	case msg.Method == nil && (msg.Result != nil || msg.Error != nil): // a response; this server never asks the client
		w.WriteHeader(http.StatusAccepted)
		return
	case msg.Method == nil:
		badRequest(w, -32600, "Invalid Request: no method")
		return
	case msg.ID == nil: // a notification (notifications/initialized and the rest): accepted, nothing to answer
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if id := bytes.TrimSpace(msg.ID); len(id) == 0 || !(id[0] == '"' || id[0] == '-' || (id[0] >= '0' && id[0] <= '9')) {
		badRequest(w, -32600, "Invalid Request: id must be a string or a number")
		return
	}
	result, rerr := s.dispatch(r, *msg.Method, msg.Params)
	reply := map[string]any{"jsonrpc": "2.0", "id": msg.ID}
	if rerr != nil {
		reply["error"] = rerr
	} else {
		reply["result"] = result
	}
	writeJSON(w, http.StatusOK, reply)
}

func (s *server) dispatch(r *http.Request, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		// the client's version is not needed: this server has one, and returning it is the negotiation (a client
		// that cannot use it disconnects)
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(params) > 0 && json.Unmarshal(params, &p) != nil {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
			"serverInfo":      map[string]string{"name": "engine-mcp", "version": serverVersion},
			"instructions":    instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(params, &p) != nil {
			return nil, &rpcError{Code: -32602, Message: "Invalid params"}
		}
		result, ok := s.callTool(r.Context(), p.Name, p.Arguments)
		if !ok {
			return nil, &rpcError{Code: -32602, Message: "Unknown tool: " + p.Name}
		}
		return result, nil
	}
	return nil, &rpcError{Code: -32601, Message: "Method not found"}
}
