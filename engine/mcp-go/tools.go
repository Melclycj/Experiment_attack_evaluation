package main

// The three tools. A host path is matched to a registered object here; the core sees only the object's alias and the
// remainder of the path, which is passed on as written (no cleaning: "..", "." and empty segments reach the worker and
// the core, which refuse them). The object list is asked for on every call and never kept, since the user can change
// it while the row runs.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// reasons are the refusal words of the file port (FILE_REFUSED.reason), in code order from 1: the closed list of 13 in
// SPEC-canonical-form.md §3.8 (validation.md H-18), the same codes the core and the worker use.
var reasons = []struct{ word, next string }{
	{"not_registered", "The path is not under any host path the user registered for this workspace. Call list_host_objects to see what is registered; anything else needs the user to register it."},
	{"op_not_granted", "The user registered this object without this operation (listing is granted per directory). Do not retry; ask the user if you need it."},
	{"bad_path", "Below the registered path every segment must be non-empty and not . or .., with no NUL byte and at most 4096 bytes in all. Write the path without .., without doubled / and without a trailing /."},
	{"outside_or_symlink", "The path leaves the registered location or passes through a symbolic link; links are not followed. Do not retry this path."},
	{"wrong_type", "read_host_file reads regular files only and list_host_directory lists directories only. Use the other tool for this path, or none if it is neither."},
	{"too_large", "One read returns 1 to 262144 bytes. Ask for a length in that range and page with offset."},
	{"user_denied", "The user denied this request. Do not retry."},
	{"pdp_denied", "The policy decision point denied this request. Do not retry."},
	{"recorded_deny", "The user recorded a deny that covers this request. Do not retry."},
	{"policy_changed", "The user's settings changed while this request waited. You may retry."},
	{"unavailable", "The engine could not take the request now: the object is unavailable, the row is closing, or the record path failed."},
	{"timeout", "The request waited too long for an answer. You may retry."},
	{"not_found", "Nothing exists at this path. Check the name with list_host_directory."},
}

const reasonNotRegistered = 1
const reasonBadPath = 3
const reasonUnavailable = 11

func reasonWord(code byte) string {
	if code >= 1 && int(code) <= len(reasons) {
		return reasons[code-1].word
	}
	return fmt.Sprintf("unknown_reason_%d", code)
}

func reasonNext(code byte) string {
	if code >= 1 && int(code) <= len(reasons) {
		return reasons[code-1].next
	}
	return "The engine refused this request."
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations map[string]bool `json:"annotations"`
}

var readOnly = map[string]bool{"readOnlyHint": true}

var toolDefs = []toolDef{
	{Name: "list_host_objects", Annotations: readOnly,
		Description: "List the host files and directories the user registered for this workspace: their absolute host " +
			"paths, type, operations (read; list for directories) and whether the user is asked each time. Read-only; " +
			"the agent's own file tools cannot reach these paths, only the two tools below can.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)},
	{Name: "list_host_directory", Annotations: readOnly,
		Description: "List a registered host directory, or a directory below one, by absolute host path: names and " +
			"types (no sizes), at most 1000 per call; when more remain, call again with start set to next_start.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"absolute host path"},` +
			`"start":{"type":"integer","minimum":0,"maximum":4294967295,"description":"index of the first entry to return, default 0"}},` +
			`"required":["path"],"additionalProperties":false}`)},
	{Name: "read_host_file", Annotations: readOnly,
		Description: "Read a registered host file, or a file below a registered directory, by absolute host path: at " +
			"most 262144 bytes from offset. UTF-8 content comes back as text, anything else as base64 (stated in the " +
			"result). Symbolic links are not followed.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{` +
			`"path":{"type":"string","description":"absolute host path"},` +
			`"offset":{"type":"integer","minimum":0,"description":"byte offset to start at, default 0"},` +
			`"length":{"type":"integer","minimum":1,"maximum":262144,"description":"bytes to read, default 262144"}},` +
			`"required":["path"],"additionalProperties":false}`)},
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError"`
}

func textResult(texts ...string) toolResult {
	r := toolResult{Content: []content{}}
	for _, t := range texts {
		r.Content = append(r.Content, content{Type: "text", Text: t})
	}
	return r
}

func errorResult(text string) toolResult {
	r := textResult(text)
	r.IsError = true
	return r
}

// failure turns an error from the file port into the agent's tool error: a refusal keeps its word and the word's next
// step; anything else (no worker, a cut connection, a reply that does not read) is reported as unavailable.
func failure(err error) toolResult {
	var r refused
	if errors.As(err, &r) {
		return errorResult(fmt.Sprintf("engine refused\nreason: %s\n%s", reasonWord(r.code), reasonNext(r.code)))
	}
	return errorResult(fmt.Sprintf("engine refused\nreason: %s\n%s\n(the file port did not answer: %v)",
		reasonWord(reasonUnavailable), reasonNext(reasonUnavailable), err))
}

func refusedHere(code byte) toolResult { return failure(refused{code}) }

// match finds the object a host path falls under: a file object only when the path equals its registered host path
// byte for byte; a directory object by the longest registered host path that equals the path or is followed in it by
// "/" (so /a/bc is not under /a/b; a registered path's own trailing "/" is not part of the directory's name). The path
// is never trimmed or cleaned: rel is every byte after that "/", so a trailing "/", "..", "." or an empty segment
// reaches the core, which refuses them (validation.md H-24).
func match(objects []hostObject, path string) (obj hostObject, rel string, ok bool) {
	best := -1
	for _, o := range objects {
		prefix := o.hostPath
		if prefix == "" {
			continue
		}
		var r string
		if !o.isDir {
			if path != prefix {
				continue
			}
		} else {
			if len(prefix) > 1 {
				prefix = strings.TrimSuffix(prefix, "/")
			}
			switch {
			case path == prefix:
				r = ""
			case !strings.HasPrefix(path, prefix):
				continue
			case prefix == "/":
				r = path[1:]
			case path[len(prefix)] == '/':
				r = path[len(prefix)+1:]
			default:
				continue
			}
		}
		if len(prefix) > best {
			best, obj, rel = len(prefix), o, r
		}
	}
	return obj, rel, best >= 0
}

// lookup opens the file port, asks for the objects and matches the path; on failure the result is the tool's answer.
func (s *server) lookup(ctx context.Context, path string) (*portConn, hostObject, string, *toolResult) {
	conn, err := dialPort(ctx, s.socket)
	if err != nil {
		r := failure(err)
		return nil, hostObject{}, "", &r
	}
	objects, err := conn.listObjects()
	if err != nil {
		conn.Close()
		r := failure(err)
		return nil, hostObject{}, "", &r
	}
	obj, rel, ok := match(objects, path)
	switch {
	case !ok:
		r := refusedHere(reasonNotRegistered)
		conn.Close()
		return nil, obj, "", &r
	case len(rel) > relPathMax: // would not fit the worker's request frame; the worker says the same of 4097 bytes
		r := refusedHere(reasonBadPath)
		conn.Close()
		return nil, obj, "", &r
	}
	return conn, obj, rel, nil
}

func (s *server) callTool(ctx context.Context, name string, args json.RawMessage) (toolResult, bool) {
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	switch name {
	case "list_host_objects":
		return s.listObjectsTool(ctx), true
	case "list_host_directory":
		var a struct {
			Path  *string `json:"path"`
			Start uint32  `json:"start"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.Path == nil {
			return errorResult("invalid arguments: path (string) is required; start is an integer 0..4294967295"), true
		}
		return s.listDirectoryTool(ctx, *a.Path, a.Start), true
	case "read_host_file":
		a := struct {
			Path   *string `json:"path"`
			Offset uint64  `json:"offset"`
			Length uint32  `json:"length"`
		}{Length: readMax}
		if err := json.Unmarshal(args, &a); err != nil || a.Path == nil {
			return errorResult("invalid arguments: path (string) is required; offset and length are non-negative integers"), true
		}
		return s.readTool(ctx, *a.Path, a.Offset, a.Length), true
	}
	return toolResult{}, false
}

func (s *server) listObjectsTool(ctx context.Context) toolResult {
	conn, err := dialPort(ctx, s.socket)
	if err != nil {
		return failure(err)
	}
	defer conn.Close()
	objects, err := conn.listObjects()
	if err != nil {
		return failure(err)
	}
	type shown struct {
		Path       string   `json:"path"`
		Type       string   `json:"type"`
		Operations []string `json:"operations"`
		Approval   string   `json:"approval"`
	}
	out := struct {
		Objects []shown `json:"objects"`
	}{Objects: []shown{}}
	for _, o := range objects {
		v := shown{Path: o.hostPath, Type: "file", Operations: []string{}, Approval: "allowed"}
		if o.isDir {
			v.Type = "directory"
		}
		if o.ops&opRead != 0 {
			v.Operations = append(v.Operations, "read")
		}
		if o.ops&opList != 0 {
			v.Operations = append(v.Operations, "list")
		}
		if o.approval == approvalAlways {
			v.Approval = "the user is asked each time"
		}
		out.Objects = append(out.Objects, v)
	}
	return jsonText(out)
}

var entryTypes = []string{"unknown", "file", "directory", "symlink", "other"}

func (s *server) listDirectoryTool(ctx context.Context, path string, start uint32) toolResult {
	conn, obj, rel, fail := s.lookup(ctx, path)
	if fail != nil {
		return *fail
	}
	defer conn.Close()
	more, entries, err := conn.list(obj.alias, rel, start)
	if err != nil {
		return failure(err)
	}
	type shown struct {
		Name       string `json:"name,omitempty"`
		NameBase64 string `json:"name_base64,omitempty"` // a name that is not UTF-8 cannot be written in a path here
		Type       string `json:"type"`
	}
	out := struct {
		Path      string  `json:"path"`
		Start     uint32  `json:"start"`
		Entries   []shown `json:"entries"`
		More      bool    `json:"more"`
		NextStart *uint64 `json:"next_start,omitempty"`
	}{Path: path, Start: start, Entries: []shown{}, More: more}
	for _, e := range entries {
		v := shown{Type: "unknown"}
		if int(e.kind) < len(entryTypes) {
			v.Type = entryTypes[e.kind]
		}
		if utf8.Valid(e.name) {
			v.Name = string(e.name)
		} else {
			v.NameBase64 = base64.StdEncoding.EncodeToString(e.name)
		}
		out.Entries = append(out.Entries, v)
	}
	if more {
		next := uint64(start) + uint64(len(entries))
		out.NextStart = &next
	}
	return jsonText(out)
}

func (s *server) readTool(ctx context.Context, path string, offset uint64, length uint32) toolResult {
	conn, obj, rel, fail := s.lookup(ctx, path)
	if fail != nil {
		return *fail
	}
	defer conn.Close()
	total, data, err := conn.read(obj.alias, rel, offset, length)
	if err != nil {
		return failure(err)
	}
	if len(data) == 0 {
		return textResult(fmt.Sprintf("%s: no bytes at offset %d; the file has %d bytes", path, offset, total))
	}
	// the bytes read back are judged whole: valid UTF-8 comes back as text, anything else (a read cut inside a
	// character included) all of it as base64; no byte is dropped and the next offset follows the last byte read
	end := offset + uint64(len(data))
	about := fmt.Sprintf("%s: bytes %d to %d of %d", path, offset, end, total)
	if end < total {
		about += fmt.Sprintf("; more remains, call again with offset %d", end)
	}
	if utf8.Valid(data) {
		return textResult(about+"; UTF-8 text in the next block", string(data))
	}
	return textResult(about+"; not valid UTF-8, so the next block is its base64 (standard, padded)",
		base64.StdEncoding.EncodeToString(data))
}

func jsonText(v any) toolResult {
	b, err := json.Marshal(v)
	if err != nil {
		return errorResult(err.Error())
	}
	return textResult(string(b))
}
