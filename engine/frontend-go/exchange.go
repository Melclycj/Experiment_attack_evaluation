package main

// One HTTP/1.1 request → one REQUEST frame on the proxy path → RESP_* frames → one HTTP/1.1 response: the translator of
// engine_frontend.py (Translator.do_ANY), with the destination the mitmproxy addon would have handed it.

import (
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
)

// what the frontend owns or must not forward (SPEC §4 条款 3 forbids them in the frame)
var dropped = map[string]bool{
	"x-engine-orig-scheme": true, "x-engine-orig-host": true, "x-engine-orig-port": true,
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "keep-alive": true,
	"te": true, "trailer": true, "upgrade": true, "expect": true,
	"proxy-connection": true, "proxy-authorization": true, "proxy-authenticate": true,
}

type destination struct {
	scheme string
	host   string // what mitmproxy's pretty_host gives: the Host header's host when there is one
	port   int
}

type front struct {
	path  *proxyPath
	certs *certStore
	inner *connQueue // tunnels whose bytes are HTTP, served by the same http.Server
}

type tunnelKey struct{}

func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if tunnel, ok := r.Context().Value(tunnelKey{}).(destination); ok {
		dest := tunnel
		if r.Host != "" {
			dest.host = prettyHost(r.Host)
		}
		if r.Method == "CONNECT" {
			fail(w, http.StatusBadRequest, "request cannot be translated")
			return
		}
		f.exchange(w, r, dest, requestPath(r))
		return
	}
	if r.Method == "CONNECT" {
		f.connect(w, r)
		return
	}
	if strings.HasPrefix(r.RequestURI, "/") || r.RequestURI == "*" { // origin-form at the proxy: the Host header names it
		host, port, hasPort, ok := parseAuthority(r.Host)
		if !ok {
			fail(w, http.StatusBadRequest, "destination unknown")
			return
		}
		if !hasPort {
			port = 80
		}
		f.exchange(w, r, destination{"http", host, port}, r.RequestURI)
		return
	}
	scheme, host, port, path, ok := absoluteTarget(r.RequestURI)
	if !ok {
		fail(w, http.StatusBadRequest, "bad request target")
		return
	}
	// net/http has already dropped the Host header of an absolute-form request (RFC 9112 §3.2.2), so the target's
	// host stands where mitmproxy's pretty_host would prefer the header (README: 已知差异)
	f.exchange(w, r, destination{scheme, host, port}, path)
}

// requestPath is the target as it reached the translator: origin-form as sent, absolute-form reduced to its path.
func requestPath(r *http.Request) string {
	if strings.HasPrefix(r.RequestURI, "/") || r.RequestURI == "*" {
		return r.RequestURI
	}
	if _, _, _, path, ok := absoluteTarget(r.RequestURI); ok {
		return path
	}
	return r.RequestURI
}

// translate builds the REQUEST frame's fields (the body travels separately); ok false is the translator's 400.
func translate(r *http.Request, dest destination, target string) (fields [][]byte, body []byte, ok bool) {
	scheme := strings.ToLower(strings.TrimSpace(dest.scheme))
	if scheme != "http" && scheme != "https" || dest.port < 0 || dest.port > 65535 {
		return nil, nil, false
	}
	host, ok := frameHost(dest.host)
	if !ok {
		return nil, nil, false
	}
	path, query := splitTarget(target)
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names) // net/http keeps no order across names; one fixed order (README: 已知差异)
	var items [][]byte
	for _, name := range names {
		lowered := strings.ToLower(name)
		if dropped[lowered] || strings.HasPrefix(lowered, "proxy-") {
			continue
		}
		for _, value := range r.Header[name] {
			items = append(items, []byte(lowered), []byte(value))
		}
	}
	if r.ContentLength > bodyLimit {
		return nil, nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1)) // chunked bodies arrive here de-chunked, Expect answered
	if err != nil || len(body) > bodyLimit {
		return nil, nil, false
	}
	port := binary.BigEndian.AppendUint16(nil, uint16(dest.port))
	return [][]byte{[]byte(r.Method), []byte(scheme), host, port, path, query, packList(items)}, body, true
}

func (f *front) exchange(w http.ResponseWriter, r *http.Request, dest destination, target string) {
	fields, body, ok := translate(r, dest, target)
	if !ok {
		fail(w, http.StatusBadRequest, "request cannot be translated")
		return
	}
	sock, err := f.path.take()
	if err != nil {
		log.Printf("WARNING proxy path unreachable: %v", err)
		fail(w, http.StatusBadGateway, "proxy path unreachable")
		return
	}
	complete := false
	defer func() {
		if complete {
			f.path.giveBack(sock)
		} else {
			sock.Close()
		}
	}()
	if err := writeRequest(sock, fields, body); err != nil {
		log.Printf("WARNING exchange failed: %v", err)
		fail(w, http.StatusBadGateway, "exchange failed")
		return
	}
	kind, head, ok := readFrame(sock)
	if !ok || kind != kindRespHead || len(head) != 3 || len(head[0]) != 1 || len(head[1]) != 2 {
		log.Printf("WARNING no response head from the connector")
		fail(w, http.StatusBadGateway, "no response from the connector")
		return
	}
	items, ok := unpackList(head[2])
	status := int(binary.BigEndian.Uint16(head[1]))
	switch category := head[0][0]; {
	case category == catRefused:
		status = http.StatusForbidden
	case category != catRemote:
		status = http.StatusBadGateway
	case status < 200 || status > 999: // never sent by the connector (it answers 1xx as result unknown)
		ok = false
	}
	if !ok || len(items)%2 != 0 {
		log.Printf("WARNING response head does not read")
		fail(w, http.StatusBadGateway, "no response from the connector")
		return
	}
	bodiless := r.Method == "HEAD" || status == http.StatusNoContent || status == http.StatusNotModified
	h := w.Header()
	h["Date"], h["Content-Type"] = nil, nil // nothing net/http would add on its own: the connector's headers only
	for i := 0; i < len(items); i += 2 {
		name := string(items[i]) // lower-case names, kept as they are (no canonicalisation)
		h[name] = append(h[name], string(items[i+1]))
	}
	rc := http.NewResponseController(w)
	w.WriteHeader(status) // HTTP/1.1 and no Content-Length: net/http frames the body as chunked unless it is bodiless
	if rc.Flush() != nil {
		panic(http.ErrAbortHandler)
	}
	for {
		kind, parts, ok := readFrame(sock)
		switch {
		case !ok: // cut before RESP_END: the client sees it cut too, never a final chunk (SPEC §3.1)
			panic(http.ErrAbortHandler)
		case kind == kindRespChunk && len(parts) == 1:
			if len(parts[0]) > 0 && !bodiless {
				if _, err := w.Write(parts[0]); err != nil || rc.Flush() != nil {
					panic(http.ErrAbortHandler)
				}
			}
		case kind == kindRespEnd && len(parts) == 0:
			complete = true // net/http writes the last chunk when the handler returns
			return
		default:
			panic(http.ErrAbortHandler)
		}
	}
}

// fail answers with a status the frontend makes itself and closes the connection, as the translator's send_error does.
func fail(w http.ResponseWriter, status int, message string) {
	h := w.Header()
	h.Set("Connection", "close")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, message+"\n")
}
