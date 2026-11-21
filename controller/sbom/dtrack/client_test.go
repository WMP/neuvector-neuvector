package dtrack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
)

const testKey = "SECRET-API-KEY-123"

type upload struct {
	Fields map[string]string
	BOM    string
	Key    string
}

type fproj struct {
	uuid, name, version, parent string // parent = parent uuid
	active                      bool
}

// fakeDT keeps projects in memory and answers like Dependency-Track (rules from the DT source).
type fakeDT struct {
	*httptest.Server
	mu          sync.Mutex
	projects    map[string]*fproj // key: name \x00 version
	seq         int
	uploads     []upload
	patches     []string // PATCH bodies
	puts        []string // PUT bodies
	calls       []string // "lookup name", "PUT name", "PATCH name", ... in order
	lookups     int
	bomStatuses []int // answers for the next uploads; 200 when empty
	bomCalls    int
	lookupCode  int // 0 = normal
	patchCode   int // 0 = normal
	putCode     int // 0 = normal
}

// add pre-creates a project and returns it.
func (f *fakeDT) add(name, version string, active bool, parent string) *fproj {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addLocked(name, version, active, parent)
}

func (f *fakeDT) addLocked(name, version string, active bool, parent string) *fproj {
	f.seq++
	p := &fproj{uuid: fmt.Sprintf("u-%d", f.seq), name: name, version: version, active: active, parent: parent}
	f.projects[name+"\x00"+version] = p
	return p
}

func (f *fakeDT) get(name, version string) *fproj {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.projects[name+"\x00"+version]
}

func (f *fakeDT) byUUID(uuid string) *fproj {
	for _, p := range f.projects {
		if p.uuid == uuid {
			return p
		}
	}
	return nil
}

func (f *fakeDT) activeChildren(uuid string) bool {
	for _, p := range f.projects {
		if p.parent == uuid && p.active {
			return true
		}
	}
	return false
}

func (f *fakeDT) callsString() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "; ")
}

func newFakeDT(t *testing.T) *fakeDT {
	f := &fakeDT{projects: map[string]*fproj{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/bom":
			f.bomCalls++
			if len(f.bomStatuses) > 0 {
				code := f.bomStatuses[0]
				f.bomStatuses = f.bomStatuses[1:]
				if code != 200 {
					w.WriteHeader(code)
					return
				}
			}
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				w.WriteHeader(400)
				return
			}
			u := upload{Fields: map[string]string{}, Key: r.Header.Get("X-Api-Key")}
			for k, v := range r.MultipartForm.Value {
				u.Fields[k] = v[0]
			}
			fh := r.MultipartForm.File["bom"][0]
			u.Fields["filename"], u.Fields["ctype"] = fh.Filename, fh.Header.Get("Content-Type")
			fd, _ := fh.Open()
			b, _ := io.ReadAll(fd)
			u.BOM = string(b)
			// parentUUID is used only when the project is auto-created; the parent must exist
			name, version := u.Fields["projectName"], u.Fields["projectVersion"]
			if f.projects[name+"\x00"+version] == nil && u.Fields["autoCreate"] == "true" {
				pu := u.Fields["parentUUID"]
				if pu != "" && f.byUUID(pu) == nil {
					w.WriteHeader(404)
					return
				}
				f.addLocked(name, version, true, pu)
			}
			f.calls = append(f.calls, "upload "+name)
			f.uploads = append(f.uploads, u)
			io.WriteString(w, `{"token":"t"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/project/lookup":
			f.lookups++
			q := r.URL.Query()
			f.calls = append(f.calls, "lookup "+q.Get("name"))
			if f.lookupCode != 0 {
				w.WriteHeader(f.lookupCode)
				return
			}
			// version absent = only projects without version
			p := f.projects[q.Get("name")+"\x00"+q.Get("version")]
			if p == nil || (!q.Has("version") && p.version != "") {
				w.WriteHeader(404)
				return
			}
			m := map[string]any{"uuid": p.uuid, "active": p.active}
			if pp := f.byUUID(p.parent); pp != nil {
				m["parent"] = map[string]any{"name": pp.name, "uuid": pp.uuid}
			}
			json.NewEncoder(w).Encode(m)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/project":
			b, _ := io.ReadAll(r.Body)
			f.puts = append(f.puts, string(b))
			var m struct {
				Name   string
				Active bool
				Parent *struct{ UUID string }
			}
			json.Unmarshal(b, &m)
			f.calls = append(f.calls, "PUT "+m.Name)
			if f.putCode != 0 {
				w.WriteHeader(f.putCode)
				return
			}
			pu := ""
			if m.Parent != nil {
				pu = m.Parent.UUID
				if pp := f.byUUID(pu); pp == nil {
					w.WriteHeader(404)
					return
				} else if !pp.active {
					w.WriteHeader(409)
					return
				}
			}
			if f.projects[m.Name+"\x00"] != nil {
				w.WriteHeader(409)
				return
			}
			p := f.addLocked(m.Name, "", m.Active, pu)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"uuid": p.uuid})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/v1/project/"):
			b, _ := io.ReadAll(r.Body)
			f.patches = append(f.patches, string(b))
			if r.Header.Get("Content-Type") != "application/json" {
				w.WriteHeader(415)
				return
			}
			if f.patchCode != 0 {
				w.WriteHeader(f.patchCode)
				return
			}
			p := f.byUUID(strings.TrimPrefix(r.URL.Path, "/api/v1/project/"))
			if p == nil {
				w.WriteHeader(404)
				return
			}
			f.calls = append(f.calls, "PATCH "+p.name)
			var m struct {
				Active *bool
				Parent *struct{ UUID string }
			}
			json.Unmarshal(b, &m)
			newParent := p.parent
			if m.Parent != nil {
				newParent = m.Parent.UUID
				if pp := f.byUUID(newParent); pp == nil {
					w.WriteHeader(404)
					return
				}
			}
			active := p.active
			if m.Active != nil {
				active = *m.Active
			}
			if pp := f.byUUID(newParent); active && pp != nil && !pp.active {
				w.WriteHeader(409) // an inactive project cannot be a parent
				return
			}
			if !active && f.activeChildren(p.uuid) {
				w.WriteHeader(409)
				return
			}
			p.active, p.parent = active, newParent
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeDT) client() *Client {
	return &Client{URL: f.URL, APIKey: testKey, HTTP: f.Client()}
}

func (f *fakeDT) counts() (uploads, patches int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads), len(f.patches)
}

// captureLogs collects all log output; the test fails if the API key is in it.
func captureLogs(t *testing.T) *safeBuf {
	buf := &safeBuf{}
	oldOut, oldLvl := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(buf)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetLevel(oldLvl)
		if strings.Contains(buf.String(), testKey) {
			t.Errorf("API key found in log output: %s", buf.String())
		}
	})
	return buf
}

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestUploadFields(t *testing.T) {
	f := newFakeDT(t)
	p := Project{Name: "c/ns/rs/app", Version: "sha256:abc", Tags: []string{"a", "b"}}
	if err := f.client().Upload(t.Context(), p, "", []byte(`{"x": 1}`)); err != nil {
		t.Fatal(err)
	}
	u := f.uploads[0]
	want := map[string]string{"autoCreate": "true", "projectName": p.Name, "projectVersion": p.Version,
		"projectTags": "a,b", "filename": "bom.json", "ctype": "application/json"}
	for k, v := range want {
		if u.Fields[k] != v {
			t.Errorf("field %s = %q, want %q", k, u.Fields[k], v)
		}
	}
	if u.Key != testKey || u.BOM != `{"x": 1}` {
		t.Errorf("key %q bom %q", u.Key, u.BOM)
	}

	if _, ok := u.Fields["parentUUID"]; ok {
		t.Error("parentUUID sent without parent")
	}
	if err := f.client().Upload(t.Context(), Project{Name: "new", Version: "v"}, "pu-1", []byte(`{}`)); err == nil {
		t.Error("unknown parent must fail with 404")
	}

	p.Tags = nil
	f.uploads = nil
	if err := f.client().Upload(t.Context(), p, "", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.uploads[0].Fields["projectTags"]; ok {
		t.Error("projectTags sent without tags")
	}
}

func TestUploadErrors(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	f.bomStatuses = []int{413, 500}
	err := f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, "", []byte("12345"))
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "413") ||
		!strings.Contains(err.Error(), "proxy-body-size") || !strings.Contains(err.Error(), "5 bytes") {
		t.Errorf("413 error: %v", err)
	}
	err = f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, "", []byte("x"))
	if err == nil || errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "500") {
		t.Errorf("500 error: %v", err)
	}
	// connection error: no key in the text
	f.Close()
	err = f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, "", []byte("x"))
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("conn error: %v", err)
	}
}

func TestSetActive(t *testing.T) {
	f := newFakeDT(t)
	c := f.client()
	ctx := t.Context()

	if err := c.SetActive(ctx, "n", "v", false); err != nil || len(f.patches) != 0 {
		t.Errorf("404: err %v patches %v", err, f.patches)
	}
	f.add("n", "v", false, "")
	if err := c.SetActive(ctx, "n", "v", false); err != nil || len(f.patches) != 0 {
		t.Errorf("already inactive: err %v patches %v", err, f.patches)
	}

	if err := c.SetActive(ctx, "n", "v", true); err != nil || len(f.patches) != 1 || f.patches[0] != `{"active":true}` {
		t.Errorf("activate: err %v patches %v", err, f.patches)
	}

	f.patchCode = 304
	if err := c.SetActive(ctx, "n", "v", false); err != nil {
		t.Errorf("304: %v", err)
	}
	f.patchCode = 409
	err := c.SetActive(ctx, "n", "v", false)
	if err == nil || !strings.Contains(err.Error(), "child") || strings.Contains(err.Error(), testKey) {
		t.Errorf("409: %v", err)
	}
	f.patchCode = 500
	if err := c.SetActive(ctx, "n", "v", false); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("500: %v", err)
	}
}

func TestNoRedirect(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("X-Api-Key") != ""
	}))
	defer other.Close()
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer dt.Close()
	c := &Client{URL: dt.URL, APIKey: testKey, HTTP: dt.Client()}
	if err := c.Upload(t.Context(), Project{Name: "n", Version: "v"}, "", []byte("{}")); err == nil {
		t.Fatal("redirect must fail the upload")
	}
	if leaked {
		t.Fatal("API key sent to the redirect target")
	}
}

func TestLookupWithoutVersionAndCreateConflict(t *testing.T) {
	f := newFakeDT(t)
	c := f.client()
	ctx := t.Context()
	f.add("n", "v1", true, "")
	if p, err := c.lookup(ctx, "n", ""); err != nil || p != nil {
		t.Errorf("a project with version must not match without version: %v %v", p, err)
	}
	rootP, err := c.create(ctx, "n", "")
	if err != nil {
		t.Fatal(err)
	}
	root := rootP.UUID
	if p, err := c.lookup(ctx, "n", ""); err != nil || p == nil || p.UUID != root {
		t.Errorf("lookup: %v %v", p, err)
	}
	if got, err := c.create(ctx, "n", ""); err != nil || got.UUID != root { // 409, then lookup
		t.Errorf("create again: %v %v", got, err)
	}
	childP, err := c.create(ctx, "child", root)
	if err != nil {
		t.Fatal(err)
	}
	child := childP.UUID
	if p, _ := c.lookup(ctx, "child", ""); p == nil || p.ParentUUID != root {
		t.Errorf("parent: %v", p)
	}
	f.get("n", "").active = false
	if _, err := c.create(ctx, "child2", root); !errors.Is(err, errRejected) {
		t.Errorf("inactive parent: %v", err)
	}
	if err := c.patch(ctx, child, nil, "nope"); !errors.Is(err, errRejected) {
		t.Errorf("unknown parent: %v", err)
	}
}
