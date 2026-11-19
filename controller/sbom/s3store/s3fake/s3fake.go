// Package s3fake is a minimal in-memory S3 server (path-style, signatures ignored) for tests.
package s3fake

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	*httptest.Server
	PageSize int // 0 = 1000

	mu       sync.Mutex
	objs     map[string][]byte
	mod      map[string]time.Time
	meta     map[string]http.Header // x-amz-meta-* headers of each object
	fail     bool
	requests int
}

func New() *Server {
	s := &Server{objs: map[string][]byte{}, mod: map[string]time.Time{}, meta: map[string]http.Header{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) Objects() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string][]byte, len(s.objs))
	for k, v := range s.objs {
		m[k] = append([]byte(nil), v...)
	}
	return m
}

func (s *Server) Put(key string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[key] = append([]byte(nil), b...)
	s.mod[key] = time.Now().UTC() // metadata of an existing object is kept
}

func (s *Server) SetFail(on bool) {
	s.mu.Lock()
	s.fail = on
	s.mu.Unlock()
}

func (s *Server) Requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests
}

func writeErr(w http.ResponseWriter, code int, c string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	if _, err := io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>`+c+`</Code><Message>`+c+`</Message></Error>`); err != nil {
		panic(err)
	}
}

type listContent struct {
	Key          string
	Size         int
	LastModified string
}

type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	Name                  string
	Prefix                string
	KeyCount              int
	MaxKeys               int
	IsTruncated           bool
	NextContinuationToken string `xml:",omitempty"`
	Contents              []listContent
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.fail {
		writeErr(w, http.StatusInternalServerError, "InternalError")
		return
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	q := r.URL.Query()
	switch {
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		s.list(w, bucket, q)
	case key == "":
		writeErr(w, http.StatusBadRequest, "InvalidRequest")
	case r.Method == http.MethodPut:
		s.objs[key] = body
		s.mod[key] = time.Now().UTC()
		s.meta[key] = http.Header{}
		for k, v := range r.Header {
			if strings.HasPrefix(k, "X-Amz-Meta-") {
				s.meta[key][k] = v
			}
		}
		w.Header().Set("ETag", `"fake"`)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		b, ok := s.objs[key]
		if !ok {
			if r.Method == http.MethodGet {
				writeErr(w, http.StatusNotFound, "NoSuchKey")
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		for k, v := range s.meta[key] {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("Last-Modified", s.mod[key].Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			if _, err := w.Write(b); err != nil {
				panic(err)
			}
		}
	case r.Method == http.MethodDelete:
		delete(s.objs, key)
		delete(s.mod, key)
		delete(s.meta, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

// list is called with s.mu held; the continuation token is the last returned key.
func (s *Server) list(w http.ResponseWriter, bucket string, q map[string][]string) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	max := s.PageSize
	if max <= 0 {
		max = 1000
	}
	if m, err := strconv.Atoi(get("max-keys")); err == nil && m > 0 && m < max {
		max = m
	}
	prefix, after := get("prefix"), get("continuation-token")
	keys := make([]string, 0, len(s.objs))
	for k := range s.objs {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	res := listResult{Name: bucket, Prefix: prefix, MaxKeys: max}
	if len(keys) > max {
		keys = keys[:max]
		res.IsTruncated = true
		res.NextContinuationToken = keys[max-1]
	}
	for _, k := range keys {
		res.Contents = append(res.Contents, listContent{k, len(s.objs[k]), s.mod[k].Format(time.RFC3339)})
	}
	res.KeyCount = len(keys)
	w.Header().Set("Content-Type", "application/xml")
	if err := xml.NewEncoder(w).Encode(res); err != nil {
		panic(err)
	}
}
