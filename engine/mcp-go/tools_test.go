package main

// The tools against a fake file worker: tools/list, read as text and as base64, directory paging, path to object by
// segment, ".." passed as written, every refusal word, no caching of the object list, and the frame limits.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestToolsListNamesAndSchemas(t *testing.T) {
	rec := post(t, noPort(t), `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	var res struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Annotations map[string]bool `json:"annotations"`
			InputSchema struct {
				Type       string                     `json:"type"`
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
				Additional *bool                      `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(decodeReply(t, rec).Result, &res); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"list_host_objects": {}, "list_host_directory": {"path", "start"},
		"read_host_file": {"path", "offset", "length"}}
	if len(res.Tools) != 3 {
		t.Fatalf("%d tools", len(res.Tools))
	}
	for _, tool := range res.Tools {
		props, ok := want[tool.Name]
		s := tool.InputSchema
		if !ok || s.Type != "object" || len(s.Properties) != len(props) || s.Additional == nil || *s.Additional ||
			tool.Description == "" || !tool.Annotations["readOnlyHint"] {
			t.Errorf("%s: %+v", tool.Name, tool)
		}
		for _, p := range props {
			if s.Properties[p] == nil {
				t.Errorf("%s: no property %s", tool.Name, p)
			}
		}
		if len(props) > 0 && (len(s.Required) != 1 || s.Required[0] != "path") {
			t.Errorf("%s: required %v", tool.Name, s.Required)
		}
	}
	var length struct{ Minimum, Maximum int }
	json.Unmarshal(res.Tools[2].InputSchema.Properties["length"], &length)
	if res.Tools[2].Name != "read_host_file" || length.Minimum != 1 || length.Maximum != readMax {
		t.Errorf("length schema %+v", length)
	}
}

func TestMatchBySegment(t *testing.T) {
	objs := []hostObject{dirObj("ab", "/a/b"), dirObj("a", "/a"), fileObj("f", "/a/f.txt"), fileObj("g", "/x/g.txt"),
		dirObj("slash", "/s/")}
	cases := []struct{ path, alias, rel string }{
		{"/a/b", "ab", ""}, {"/a/b/", "ab", ""}, {"/a/b/c/d", "ab", "c/d"},
		{"/a/bc", "a", "bc"},                                  // /a/b is not a prefix of /a/bc; /a is
		{"/a/f.txt", "f", ""}, {"/a/f.txt/x", "a", "f.txt/x"}, // a file object only by the whole path
		{"/x/g.txt", "g", ""}, {"/x/g.txt/y", "", ""}, {"/x", "", ""}, {"/x/g.txtt", "", ""},
		{"/a/b/../c", "ab", "../c"}, {"/a/b/./c", "ab", "./c"}, {"/a/b//c", "ab", "/c"}, {"/a/b/c\x00d", "ab", "c\x00d"},
		{"/s/t", "slash", "t"}, {"/s", "slash", ""},
		{"a/b", "", ""}, {"", "", ""}, {"/", "", ""}, {"/ab", "", ""},
		// the request path is never trimmed: a trailing "/" stays in what the core gets (and refuses as bad_path),
		// and a file object takes its whole path only, so "/x/g.txt/" is no object and "/a/f.txt/" is under /a
		{"/x/g.txt/", "", ""}, {"/a/f.txt/", "a", "f.txt/"}, {"/a/b/c/", "ab", "c/"}, {"/a/b/c//", "ab", "c//"},
		{"/s/t/", "slash", "t/"},
	}
	for _, c := range cases {
		o, rel, ok := match(objs, c.path)
		if ok != (c.alias != "") || o.alias != c.alias || rel != c.rel {
			t.Errorf("%q: got %q %q %v, want %q %q", c.path, o.alias, rel, ok, c.alias, c.rel)
		}
	}
	root := []hostObject{dirObj("root", "/")}
	for path, rel := range map[string]string{"/": "", "/etc/x": "etc/x", "//etc": "/etc"} {
		if o, r, ok := match(root, path); !ok || o.alias != "root" || r != rel {
			t.Errorf("root %q: %q %q %v", path, o.alias, r, ok)
		}
	}
	if _, _, ok := match([]hostObject{dirObj("ab", "/a/b")}, "/a/bc"); ok {
		t.Error("/a/bc matched /a/b")
	}
}

func notesWorker(op func(r fakeReq) []byte) func(r fakeReq) []byte {
	return worker(op, dirObj("notes", "/home/u/notes"), fileObj("cfg", "/etc/app.conf"))
}

func TestReadText(t *testing.T) {
	text := "hello 世界\nline two\n"
	f := newFakePort(t, notesWorker(func(r fakeReq) []byte { return dataReply(uint64(len(text)), []byte(text)) }))
	res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/home/u/notes/a.txt"})
	if res.IsError || len(res.Content) != 2 || res.Content[1].Text != text || !strings.Contains(res.Content[0].Text, "UTF-8 text") ||
		strings.Contains(res.Content[0].Text, "more remains") {
		t.Fatalf("%+v", res)
	}
	if !equalKinds(f.kinds(), kindListObjects, kindRead) {
		t.Fatalf("requests %x", f.kinds())
	}
	if a, rel, off, n := readFields(f.last()); a != "notes" || rel != "a.txt" || off != 0 || n != readMax {
		t.Errorf("FILE_READ %q %q %d %d", a, rel, off, n)
	}
	// a file object: the whole path, the empty relative path; offset and length as given
	call(t, testServer(f), "read_host_file", map[string]any{"path": "/etc/app.conf", "offset": 7, "length": 3})
	if a, rel, off, n := readFields(f.last()); a != "cfg" || rel != "" || off != 7 || n != 3 {
		t.Errorf("FILE_READ %q %q %d %d", a, rel, off, n)
	}
}

func TestReadBinaryAsBase64(t *testing.T) {
	data := []byte{0xff, 0x00, 0x80, 'x', 0xc3}
	f := newFakePort(t, notesWorker(func(r fakeReq) []byte { return dataReply(5, data) }))
	res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/home/u/notes/b.bin"})
	got, err := base64.StdEncoding.DecodeString(res.Content[1].Text)
	if res.IsError || err != nil || !bytes.Equal(got, data) || !strings.Contains(res.Content[0].Text, "base64") {
		t.Fatalf("%+v", res)
	}
}

func TestReadCutInsideACharacterIsWholeBase64(t *testing.T) {
	// H-24: the bytes read back are judged whole; "ab" and the first two bytes of 中 are not valid UTF-8, so all four
	// come back as base64, none dropped, and the next offset is right after them
	part := []byte("ab\xe4\xb8")
	f := newFakePort(t, notesWorker(func(r fakeReq) []byte { return dataReply(10, part) }))
	res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/home/u/notes/c.txt", "length": 4})
	got, err := base64.StdEncoding.DecodeString(res.Content[1].Text)
	if res.IsError || err != nil || !bytes.Equal(got, part) || !strings.Contains(res.Content[0].Text, "base64") ||
		!strings.Contains(res.Content[0].Text, "bytes 0 to 4 of 10") || !strings.Contains(res.Content[0].Text, "offset 4") {
		t.Fatalf("%+v", res)
	}
	// past the end: no bytes, the size
	f2 := newFakePort(t, notesWorker(func(r fakeReq) []byte { return dataReply(5, nil) }))
	res = call(t, testServer(f2), "read_host_file", map[string]any{"path": "/home/u/notes/c.txt", "offset": 9})
	if res.IsError || len(res.Content) != 1 || !strings.Contains(res.Content[0].Text, "has 5 bytes") {
		t.Fatalf("%+v", res)
	}
}

func TestBadArgumentsNeverReachThePort(t *testing.T) {
	s := noPort(t)
	for _, args := range []map[string]any{{}, {"path": 3}, {"path": "/a", "length": -1}, {"path": "/a", "offset": -2},
		{"path": "/a", "length": 1 << 33}, {"path": "/a", "offset": 1.5}} {
		if res := call(t, s, "read_host_file", args); !res.IsError || !strings.Contains(res.Content[0].Text, "invalid arguments") {
			t.Errorf("%v: %+v", args, res)
		}
	}
	if res := call(t, s, "list_host_directory", map[string]any{"path": "/a", "start": -1}); !res.IsError {
		t.Errorf("start -1: %+v", res)
	}
}

func TestListDirectoryPages(t *testing.T) {
	page := make([]dirEntry, listMax)
	for i := range page {
		page[i] = dirEntry{name: []byte(fmt.Sprintf("f%04d", i)), kind: 1}
	}
	tail := []dirEntry{{[]byte("sub"), 2}, {[]byte("ln"), 3}, {[]byte("fifo"), 4}, {[]byte("odd"), 0},
		{[]byte("bad\xff"), 1}}
	f := newFakePort(t, notesWorker(func(r fakeReq) []byte {
		if binary.BigEndian.Uint32(r.fields[2]) == 0 {
			return entriesReply(true, page...)
		}
		return entriesReply(false, tail...)
	}))
	type listing struct {
		Path    string `json:"path"`
		Entries []struct {
			Name       string `json:"name"`
			NameBase64 string `json:"name_base64"`
			Type       string `json:"type"`
		} `json:"entries"`
		More      bool    `json:"more"`
		NextStart *uint64 `json:"next_start"`
	}
	var first, second listing
	res := call(t, testServer(f), "list_host_directory", map[string]any{"path": "/home/u/notes/"})
	json.Unmarshal([]byte(res.Content[0].Text), &first)
	if res.IsError || len(first.Entries) != listMax || !first.More || first.NextStart == nil || *first.NextStart != 1000 ||
		first.Entries[999].Name != "f0999" || first.Entries[0].Type != "file" {
		t.Fatalf("first page: more %v next %v n %d", first.More, first.NextStart, len(first.Entries))
	}
	if r := f.last(); r.kind != kindList || string(r.fields[0]) != "notes" || string(r.fields[1]) != "" {
		t.Fatalf("FILE_LIST %q %q", r.fields[0], r.fields[1])
	}
	res = call(t, testServer(f), "list_host_directory", map[string]any{"path": "/home/u/notes", "start": *first.NextStart})
	json.Unmarshal([]byte(res.Content[0].Text), &second)
	if binary.BigEndian.Uint32(f.last().fields[2]) != 1000 || second.More || second.NextStart != nil || len(second.Entries) != 5 {
		t.Fatalf("second page: %s", res.Content[0].Text)
	}
	types := []string{}
	for _, e := range second.Entries {
		types = append(types, e.Type)
	}
	if strings.Join(types, ",") != "directory,symlink,other,unknown,file" || second.Entries[4].Name != "" ||
		second.Entries[4].NameBase64 != base64.StdEncoding.EncodeToString([]byte("bad\xff")) {
		t.Errorf("entries %+v", second.Entries)
	}
}

func TestUnregisteredPathNeverReachesTheWorker(t *testing.T) {
	f := newFakePort(t, worker(func(r fakeReq) []byte { t.Error("an operation was sent"); return nil }, dirObj("ab", "/a/b")))
	for _, path := range []string{"/a/bc", "/a", "/etc/hostname", "a/b/x", ""} {
		res := call(t, testServer(f), "read_host_file", map[string]any{"path": path})
		if !res.IsError || !strings.Contains(res.Content[0].Text, "reason: not_registered\n"+reasons[0].next) {
			t.Errorf("%q: %+v", path, res)
		}
	}
	for _, k := range f.kinds() {
		if k != kindListObjects {
			t.Fatalf("requests %x", f.kinds())
		}
	}
}

func TestDotDotIsPassedAsWritten(t *testing.T) {
	f := newFakePort(t, worker(func(r fakeReq) []byte { return refusedReply(reasonBadPath) }, dirObj("ab", "/a/b")))
	res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/../secret"})
	if _, rel, _, _ := readFields(f.last()); rel != "../secret" {
		t.Fatalf("relative path %q", rel)
	}
	if !res.IsError || !strings.Contains(res.Content[0].Text, "reason: bad_path") {
		t.Fatalf("%+v", res)
	}
}

func TestEveryRefusalWordReachesTheAgent(t *testing.T) {
	seen := map[string]bool{}
	for code := byte(1); int(code) <= len(reasons); code++ {
		f := newFakePort(t, worker(func(r fakeReq) []byte { return refusedReply(code) }, dirObj("ab", "/a/b")))
		res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/x"})
		word, next := reasons[code-1].word, reasons[code-1].next
		if !res.IsError || res.Content[0].Text != "engine refused\nreason: "+word+"\n"+next || next == "" || seen[word] {
			t.Errorf("code %d: %+v", code, res)
		}
		seen[word] = true
		// a refusal of the object list itself (the core's answer may be timeout or unavailable) passes the same way
		f2 := newFakePort(t, func(r fakeReq) []byte { return refusedReply(code) })
		if res := call(t, testServer(f2), "list_host_objects", nil); !strings.Contains(res.Content[0].Text, "reason: "+word+"\n") {
			t.Errorf("code %d on the object list: %+v", code, res)
		}
	}
	if reasonWord(99) != "unknown_reason_99" || reasonWord(0) != "unknown_reason_0" || reasonWord(14) != "unknown_reason_14" {
		t.Error(reasonWord(99), reasonWord(0), reasonWord(14))
	}
}

// TestEachCodeShowsAsSpecWord pins the code-to-word table to SPEC-canonical-form.md §3.8 (validation.md H-18): the core
// and the worker send these codes, so code n must show as the n-th word there and nowhere else.
func TestEachCodeShowsAsSpecWord(t *testing.T) {
	spec := []string{"not_registered", "op_not_granted", "bad_path", "outside_or_symlink", "wrong_type", "too_large",
		"user_denied", "pdp_denied", "recorded_deny", "policy_changed", "unavailable", "timeout", "not_found"}
	if len(reasons) != len(spec) {
		t.Fatalf("%d words, SPEC has %d", len(reasons), len(spec))
	}
	for i, word := range spec {
		code := byte(i + 1)
		f := newFakePort(t, worker(func(r fakeReq) []byte { return refusedReply(code) }, dirObj("ab", "/a/b")))
		res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/x"})
		if !res.IsError || !strings.HasPrefix(res.Content[0].Text, "engine refused\nreason: "+word+"\n") {
			t.Errorf("code %d shows as %q, SPEC says %s", code, res.Content[0].Text, word)
		}
	}
	if reasonUnavailable != 11 || reasons[reasonUnavailable-1].word != "unavailable" ||
		reasons[reasonNotRegistered-1].word != "not_registered" || reasons[reasonBadPath-1].word != "bad_path" {
		t.Error("a named code is off the table")
	}
	// a port failure (no reply that reads) is shown as unavailable, code 11, as the core's own unavailable is
	f := newFakePort(t, func(r fakeReq) []byte { return nil })
	if res := call(t, testServer(f), "list_host_objects", nil); !strings.HasPrefix(res.Content[0].Text,
		"engine refused\nreason: unavailable\n") {
		t.Errorf("port failure: %+v", res)
	}
}

func TestObjectsAreAskedOnEveryCall(t *testing.T) {
	var calls atomic.Int32
	f := newFakePort(t, func(r fakeReq) []byte {
		if r.kind == kindListObjects {
			if calls.Add(1) == 1 {
				return objectsReply(dirObj("ab", "/a/b"), hostObject{alias: "q", hostPath: "/q", isDir: true, ops: opRead,
					approval: approvalAlways})
			}
			return objectsReply() // the user removed them
		}
		return dataReply(1, []byte("x"))
	})
	s := testServer(f)
	var shown struct {
		Objects []struct {
			Path, Type, Approval string
			Operations           []string
		}
	}
	res := call(t, s, "list_host_objects", map[string]any{})
	json.Unmarshal([]byte(res.Content[0].Text), &shown)
	if len(shown.Objects) != 2 || shown.Objects[0].Path != "/a/b" || shown.Objects[0].Type != "directory" ||
		strings.Join(shown.Objects[0].Operations, ",") != "read,list" || shown.Objects[0].Approval != "allowed" ||
		strings.Join(shown.Objects[1].Operations, ",") != "read" || !strings.Contains(shown.Objects[1].Approval, "asked") {
		t.Fatalf("%s", res.Content[0].Text)
	}
	if res := call(t, s, "read_host_file", map[string]any{"path": "/a/b/x"}); !strings.Contains(res.Content[0].Text, "not_registered") {
		t.Fatalf("%+v", res)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("object list asked %d times", n)
	}
}

func TestFrameLimits(t *testing.T) {
	// a remainder of 4096 bytes is sent, in a request frame under 8 KiB; 4097 is refused here
	f := newFakePort(t, worker(func(r fakeReq) []byte { return dataReply(0, nil) }, dirObj("ab", "/a/b")))
	call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/" + strings.Repeat("x", relPathMax)})
	if r := f.last(); r.kind != kindRead || len(r.fields[1]) != relPathMax || r.size > requestFrameLimit {
		t.Fatalf("kind %#x, path %d, frame %d", r.kind, len(r.fields[1]), r.size)
	}
	n := len(f.kinds())
	res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/" + strings.Repeat("x", relPathMax+1)})
	if !strings.Contains(res.Content[0].Text, "reason: bad_path") || len(f.kinds()) != n+1 || f.last().kind != kindListObjects {
		t.Fatalf("%+v %x", res, f.kinds())
	}
	// the largest object list fits the reply limit; one more object does not read
	objs := make([]hostObject, objectsMax)
	for i := range objs {
		alias := fmt.Sprintf("%064d", i)
		objs[i] = dirObj(alias, "/"+alias+strings.Repeat("p", 4096-65))
	}
	if frame := objectsReply(objs...); len(frame)-4 > replyFrameLimit {
		t.Fatalf("128 objects need %d bytes", len(frame)-4)
	}
	f = newFakePort(t, worker(nil, objs...))
	if res := call(t, testServer(f), "list_host_objects", nil); res.IsError {
		t.Fatalf("128 objects: %s", res.Content[0].Text)
	}
	f = newFakePort(t, worker(nil, append(objs, dirObj("x", "/x"))...))
	if res := call(t, testServer(f), "list_host_objects", nil); !strings.Contains(res.Content[0].Text, "reason: unavailable") {
		t.Fatalf("129 objects: %+v", res)
	}
	// a read of 256 KiB comes through; more data than that does not read
	full := bytes.Repeat([]byte("y"), readMax)
	f = newFakePort(t, worker(func(r fakeReq) []byte { return dataReply(readMax, full) }, dirObj("ab", "/a/b")))
	if res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/y"}); len(res.Content) != 2 || len(res.Content[1].Text) != readMax {
		t.Fatalf("256 KiB read: %+v", res.IsError)
	}
	f = newFakePort(t, worker(func(r fakeReq) []byte { return dataReply(readMax+1, append(full, 'y')) }, dirObj("ab", "/a/b")))
	if res := call(t, testServer(f), "read_host_file", map[string]any{"path": "/a/b/y"}); !strings.Contains(res.Content[0].Text, "reason: unavailable") {
		t.Fatalf("over 256 KiB: %+v", res.IsError)
	}
	// a reply frame announced over the limit is refused on its length word, without waiting for its body
	f = newFakePort(t, func(r fakeReq) []byte { return binary.BigEndian.AppendUint32(nil, replyFrameLimit+1) })
	done := make(chan string, 1)
	go func() {
		rec := post(t, testServer(f), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_host_objects"}}`)
		done <- rec.Body.String()
	}()
	select {
	case body := <-done:
		if !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "reason: unavailable") {
			t.Fatalf("oversize reply: %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the body of an oversize reply was waited for")
	}
}

func TestPortFailuresAreUnavailable(t *testing.T) {
	cases := map[string]func(r fakeReq) []byte{
		"closed":     func(r fakeReq) []byte { return nil },
		"wrong kind": func(r fakeReq) []byte { return dataReply(0, nil) },
		"fields":     func(r fakeReq) []byte { return packFrame(kindObjects) },
		"bad list":   func(r fakeReq) []byte { return packFrame(kindObjects, []byte{0, 0, 0, 2}) },
		"type": func(r fakeReq) []byte {
			return packFrame(kindObjects, packList([][]byte{packList([][]byte{[]byte("a"), []byte("/a"), {9}, {1}, {1}})}))
		},
	}
	for name, h := range cases {
		res := call(t, testServer(newFakePort(t, h)), "list_host_objects", nil)
		if !res.IsError || !strings.Contains(res.Content[0].Text, "reason: unavailable") ||
			!strings.Contains(res.Content[0].Text, "did not answer") {
			t.Errorf("%s: %+v", name, res)
		}
	}
	s := newServer("/nonexistent/file.sock", 3129)
	if res := call(t, s, "read_host_file", map[string]any{"path": "/a"}); !strings.Contains(res.Content[0].Text, "reason: unavailable") {
		t.Errorf("no socket: %+v", res)
	}
}

func TestListsDecode(t *testing.T) {
	for _, c := range []struct {
		data []byte
		max  int
		ok   bool
	}{
		{packList([][]byte{[]byte("a"), nil}), 2, true}, {packList([][]byte{[]byte("a"), nil}), 1, false},
		{append(packList([][]byte{[]byte("a")}), 0), 5, false}, {[]byte{0, 0, 0, 1, 0, 0, 0, 9, 'a'}, 5, false},
		{[]byte{0, 0, 0}, 5, false}, {packList(nil), 0, true},
	} {
		if _, ok := unpackList(c.data, c.max); ok != c.ok {
			t.Errorf("%x max %d: %v", c.data, c.max, ok)
		}
	}
	var buf bytes.Buffer
	buf.Write(packFrame(kindRead, []byte("al"), []byte("p/q"), u64(1), u32(2)))
	kind, fields, err := readFrame(&buf, requestFrameLimit)
	if err != nil || kind != kindRead || len(fields) != 4 || string(fields[1]) != "p/q" {
		t.Errorf("%#x %q %v", kind, fields, err)
	}
	if _, _, err := readFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 8); err == nil {
		t.Error("an empty frame read")
	}
}
