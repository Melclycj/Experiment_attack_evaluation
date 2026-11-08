package main

// Where a request goes, derived the way mitmproxy 12.3.1 derives it for the Python frontend (mitmproxy/net/http/url.py
// parse_authority, mitmproxy/net/check.py is_valid_host, http1/read.py _read_request_line, http.py pretty_host), then
// normalised the way engine_frontend.py's translator does (_canonical_request).

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var (
	authorityRe = regexp.MustCompile(`^([^:]+|\[.+\])(?::([0-9]+))?$`)
	labelRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
)

// validHost is is_valid_host for ASCII names. A non-ASCII name is invalid here; mitmproxy would IDNA-encode it first
// (README: 已知差异).
func validHost(h string) bool {
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return false
		}
	}
	labels := strings.Split(h, ".") // Python's idna codec, ASCII fast path: only the last label may be empty
	for _, l := range labels[:len(labels)-1] {
		if len(l) == 0 || len(l) >= 64 {
			return false
		}
	}
	if len(labels[len(labels)-1]) >= 64 || len(h) > 255 {
		return false
	}
	h = strings.TrimSuffix(h, ".")
	names := true
	for _, l := range strings.Split(h, ".") {
		if !labelRe.MatchString(l) {
			names = false
			break
		}
	}
	if names {
		return true
	}
	_, err := netip.ParseAddr(h)
	return err == nil
}

// parseAuthority is parse_authority(check=True): host without brackets, the port if one is written, ok false when the
// authority does not read.
func parseAuthority(a string) (host string, port int, hasPort, ok bool) {
	m := authorityRe.FindStringSubmatch(a)
	if m == nil {
		return "", 0, false, false
	}
	host = m[1]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if !validHost(host) {
		return "", 0, false, false
	}
	if m[2] == "" {
		return host, 0, false, true
	}
	port, err := strconv.Atoi(m[2])
	if err != nil || port > 65535 {
		return "", 0, false, false
	}
	return host, port, true, true
}

// prettyHost is parse_authority(check=False)[0]: the host of a readable authority, else the authority unchanged.
func prettyHost(a string) string {
	if h, _, _, ok := parseAuthority(a); ok {
		return h
	}
	return a
}

func defaultPort(scheme string) int { // url.default_port: exact, lower-case scheme only
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

// absoluteTarget splits an absolute-form target as _read_request_line does: authority up to the first "/", the rest
// (from that "/") is the path with its query.
func absoluteTarget(target string) (scheme, host string, port int, path string, ok bool) {
	scheme, rest, found := strings.Cut(target, "://")
	if !found {
		return "", "", 0, "", false
	}
	authority, tail, _ := strings.Cut(rest, "/")
	host, port, _, ok = parseAuthority(authority)
	if !ok {
		return "", "", 0, "", false
	}
	if port == 0 { // `port or default_port(scheme)`: an explicit :0 also takes the default
		port = defaultPort(scheme)
	}
	if port == 0 {
		return "", "", 0, "", false
	}
	return scheme, host, port, "/" + tail, true
}

// frameHost is the translator's host normalisation; ok is false where the translator answers 400 (and, unlike the
// translator, for any byte above 0x7E, which the translator would IDNA-encode).
func frameHost(h string) ([]byte, bool) {
	h = strings.TrimRight(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" {
		return nil, false
	}
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	for i := 0; i < len(h); i++ {
		if h[i] > 0x7E {
			return nil, false
		}
	}
	return []byte(h), true
}

// splitTarget is the translator's path handling: the leading-"//" reduction of http.server's parse_request (Python
// 3.12), then path and query split at the first "?", and a "/" put in front of a path that lacks one.
func splitTarget(target string) (path, query []byte) {
	if strings.HasPrefix(target, "//") {
		target = "/" + strings.TrimLeft(target, "/")
	}
	p, q, _ := strings.Cut(target, "?")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return []byte(p), []byte(q)
}
