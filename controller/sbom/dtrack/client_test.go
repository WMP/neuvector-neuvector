package dtrack

import (
	"bytes"
	"encoding/json"
	"errors"
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

// fakeDT records calls and answers like Dependency-Track.
type fakeDT struct {
	*httptest.Server
	mu          sync.Mutex
	uploads     []upload
	patches     []string // PATCH bodies
	lookups     int
	bomStatuses []int // answers for the next uploads; 200 when empty
	bomCalls    int
	lookupCode  int  // 0 = 200
	active      bool // active flag in the lookup answer
	patchCode   int  // 0 = 200
}

func newFakeDT(t *testing.T) *fakeDT {
	f := &fakeDT{active: true}
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
			f.uploads = append(f.uploads, u)
			io.WriteString(w, `{"token":"t"}`)
		case r.URL.Path == "/api/v1/project/lookup":
			f.lookups++
			if f.lookupCode != 0 {
				w.WriteHeader(f.lookupCode)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"uuid": "u-1", "active": f.active})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/project/u-1":
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
			var m map[string]bool
			json.Unmarshal(b, &m)
			f.active = m["active"]
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
	if err := f.client().Upload(t.Context(), p, []byte(`{"x": 1}`)); err != nil {
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

	p.Tags = nil
	f.uploads = nil
	if err := f.client().Upload(t.Context(), p, []byte(`{}`)); err != nil {
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
	err := f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, []byte("12345"))
	if !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "413") ||
		!strings.Contains(err.Error(), "proxy-body-size") || !strings.Contains(err.Error(), "5 bytes") {
		t.Errorf("413 error: %v", err)
	}
	err = f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, []byte("x"))
	if err == nil || errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "500") {
		t.Errorf("500 error: %v", err)
	}
	// connection error: no key in the text
	f.Close()
	err = f.client().Upload(t.Context(), Project{Name: "n", Version: "v"}, []byte("x"))
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Errorf("conn error: %v", err)
	}
}

func TestSetActive(t *testing.T) {
	f := newFakeDT(t)
	c := f.client()
	ctx := t.Context()

	f.lookupCode = 404
	if err := c.SetActive(ctx, "n", "v", false); err != nil || len(f.patches) != 0 {
		t.Errorf("404: err %v patches %v", err, f.patches)
	}
	f.lookupCode = 0

	f.active = false
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
	if err := c.Upload(t.Context(), Project{Name: "n", Version: "v"}, []byte("{}")); err == nil {
		t.Fatal("redirect must fail the upload")
	}
	if leaked {
		t.Fatal("API key sent to the redirect target")
	}
}
