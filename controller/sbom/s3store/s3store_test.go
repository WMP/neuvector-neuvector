package s3store

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/controller/sbom/s3store/s3fake"
	"github.com/neuvector/neuvector/share"
)

const secret = "TOPSECRETKEYVALUE"

var (
	dg1 = "sha256:" + strings.Repeat("a", 64)
	dg2 = "sha256:" + strings.Repeat("b", 64)
)

func testCfg(url string) share.CLUSSBOMStorage {
	return share.CLUSSBOMStorage{Enabled: true, Endpoint: url, Bucket: "bkt", Prefix: "pre", PathStyle: true, AccessKey: "AKIDTEST", SecretKey: secret}
}

func newStore(t *testing.T, srv *s3fake.Server) *Store {
	s, err := New(testCfg(srv.URL), "c1", http.DefaultClient)
	require.NoError(t, err)
	return s
}

func TestRoundtrip(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	s := newStore(t, srv)
	ctx := context.Background()

	_, err := s.Open(ctx, dg1)
	require.True(t, errors.Is(err, ErrNotFound))

	require.NoError(t, s.Put(ctx, dg1, []byte("gzdata")))
	require.NoError(t, s.Put(ctx, dg1, []byte("gzdata2"))) // overwrite
	require.Equal(t, map[string][]byte{"pre/c1/images/" + dg1 + ".cdx.json.gz": []byte("gzdata2")}, srv.Objects())

	rc, err := s.Open(ctx, dg1)
	require.NoError(t, err)
	b, _ := io.ReadAll(rc)
	rc.Close()
	require.Equal(t, "gzdata2", string(b))

	require.NoError(t, s.Delete(ctx, dg1))
	require.Empty(t, srv.Objects())
}

func TestList(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	srv.PageSize = 2
	s := newStore(t, srv)
	base := "pre/c1/images/"
	for i := 0; i < 5; i++ {
		srv.Put(base+"sha256:"+strings.Repeat(string(rune('0'+i)), 64)+".cdx.json.gz", []byte("x"))
	}
	for _, k := range []string{
		"pre/c2/images/" + dg1 + ".cdx.json.gz",
		"other/c1/images/" + dg1 + ".cdx.json.gz",
		base + "x.txt",
		base + "sha256:" + strings.Repeat("A", 64) + ".cdx.json.gz",
		base + "../sha256:" + strings.Repeat("a", 64) + ".cdx.json.gz",
		base + "a/" + dg1 + ".cdx.json.gz",
		base + dg1 + ".cdx.json.gz.bak",
	} {
		srv.Put(k, []byte("y"))
	}
	objs, err := s.List(context.Background())
	require.NoError(t, err)
	require.Len(t, objs, 5)
	for _, o := range objs {
		require.True(t, ValidDigest(o.Digest))
		require.EqualValues(t, 1, o.Size)
		require.False(t, o.LastModified.IsZero())
	}
}

func TestKey(t *testing.T) {
	s, err := New(share.CLUSSBOMStorage{Bucket: "bkt"}, "c1", http.DefaultClient)
	require.NoError(t, err)
	k, err := s.Key(dg1)
	require.NoError(t, err)
	require.Equal(t, "c1/images/"+dg1+".cdx.json.gz", k)
	for _, d := range []string{"", "../x", "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 63) + "/",
		"sha256:" + strings.Repeat("A", 64), "sha512:" + strings.Repeat("a", 64), "sha1:" + strings.Repeat("a", 40)} {
		_, err := s.Key(d)
		require.Error(t, err, d)
	}
	require.True(t, ValidDigest("sha512:"+strings.Repeat("0", 128)))

	s, err = New(share.CLUSSBOMStorage{Bucket: "bkt", Prefix: "/p/q/"}, "a/b", http.DefaultClient)
	require.NoError(t, err)
	k, _ = s.Key(dg1)
	require.Equal(t, "p/q/a%2Fb/images/"+dg1+".cdx.json.gz", k)

	for _, c := range []string{"", ".", ".."} {
		_, err = New(share.CLUSSBOMStorage{Bucket: "bkt"}, c, http.DefaultClient)
		require.Error(t, err, c)
	}
}

func TestValidate(t *testing.T) {
	ok := func(mod func(*share.CLUSSBOMStorage)) share.CLUSSBOMStorage {
		c := share.CLUSSBOMStorage{Enabled: true, Bucket: "my-bucket"}
		mod(&c)
		return c
	}
	long := strings.Repeat("a", 64)
	tests := []struct {
		name string
		mod  func(*share.CLUSSBOMStorage)
		ok   bool
	}{
		{"minimal", func(c *share.CLUSSBOMStorage) {}, true},
		{"endpoint https", func(c *share.CLUSSBOMStorage) { c.Endpoint = "https://minio.local:9000/" }, true},
		{"endpoint ftp", func(c *share.CLUSSBOMStorage) { c.Endpoint = "ftp://x" }, false},
		{"endpoint no host", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://" }, false},
		{"endpoint userinfo", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://u:p@h" }, false},
		{"endpoint query", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://h/?a=b" }, false},
		{"endpoint raw query", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://h?" }, false},
		{"endpoint fragment", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://h#" }, false},
		{"endpoint path", func(c *share.CLUSSBOMStorage) { c.Endpoint = "http://h/x" }, false},
		{"region ok", func(c *share.CLUSSBOMStorage) { c.Region = "eu-west-1" }, true},
		{"region upper", func(c *share.CLUSSBOMStorage) { c.Region = "EU" }, false},
		{"region long", func(c *share.CLUSSBOMStorage) { c.Region = long + "a" }, false},
		{"bucket missing", func(c *share.CLUSSBOMStorage) { c.Bucket = "" }, false},
		{"bucket missing disabled", func(c *share.CLUSSBOMStorage) { c.Bucket = ""; c.Enabled = false }, true},
		{"bucket short", func(c *share.CLUSSBOMStorage) { c.Bucket = "ab" }, false},
		{"bucket upper", func(c *share.CLUSSBOMStorage) { c.Bucket = "Abc" }, false},
		{"bucket dots", func(c *share.CLUSSBOMStorage) { c.Bucket = "a..b" }, false},
		{"bucket dash end", func(c *share.CLUSSBOMStorage) { c.Bucket = "abc-" }, false},
		{"bucket long", func(c *share.CLUSSBOMStorage) { c.Bucket = long }, false},
		{"prefix ok", func(c *share.CLUSSBOMStorage) { c.Prefix = "/a/b/" }, true},
		{"prefix empty seg", func(c *share.CLUSSBOMStorage) { c.Prefix = "a//b" }, false},
		{"prefix dot", func(c *share.CLUSSBOMStorage) { c.Prefix = "a/./b" }, false},
		{"prefix dotdot", func(c *share.CLUSSBOMStorage) { c.Prefix = "a/../b" }, false},
		{"prefix backslash", func(c *share.CLUSSBOMStorage) { c.Prefix = `a\b` }, false},
		{"prefix control", func(c *share.CLUSSBOMStorage) { c.Prefix = "a\nb" }, false},
		{"prefix long", func(c *share.CLUSSBOMStorage) { c.Prefix = strings.Repeat("a", 257) }, false},
		{"keys ok", func(c *share.CLUSSBOMStorage) { c.AccessKey, c.SecretKey = "a", "b" }, true},
		{"only access", func(c *share.CLUSSBOMStorage) { c.AccessKey = "a" }, false},
		{"only secret", func(c *share.CLUSSBOMStorage) { c.SecretKey = "b" }, false},
		{"key space", func(c *share.CLUSSBOMStorage) { c.AccessKey, c.SecretKey = "a", " b" }, false},
		{"key control", func(c *share.CLUSSBOMStorage) { c.AccessKey, c.SecretKey = "a\t", "b" }, false},
		{"grace max", func(c *share.CLUSSBOMStorage) { c.DeleteGrace = MaxGraceMinutes }, true},
		{"grace over", func(c *share.CLUSSBOMStorage) { c.DeleteGrace = MaxGraceMinutes + 1 }, false},
	}
	for _, tc := range tests {
		err := Validate(ok(tc.mod))
		if tc.ok {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
		}
	}
}

func TestFailureAndSecret(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := s3fake.New()
	defer srv.Close()
	// record all headers and bodies reaching the fake server
	wrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		for k, v := range r.Header {
			seen = append(seen, k+": "+strings.Join(v, ","))
		}
		seen = append(seen, string(b), r.URL.String())
		mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		r.Host = ""
		h := srv.Config.Handler
		h.ServeHTTP(w, r)
	}))
	defer wrap.Close()

	s, err := New(testCfg(wrap.URL), "c1", http.DefaultClient)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, s.Put(ctx, dg1, []byte("data")))
	mu.Lock()
	all := strings.Join(seen, "\n")
	mu.Unlock()
	require.NotContains(t, all, secret)
	require.Contains(t, all, "Credential=AKIDTEST/")

	srv.SetFail(true)
	err = s.Put(ctx, dg2, []byte("data"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), secret)
	require.Greater(t, srv.Requests(), 1)
}

func TestConfigure(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	cfg := &share.CLUSSystemConfig{ClusterName: "c1", SBOMStorage: testCfg(srv.URL)}

	cfg.SBOMStorage.Enabled = false
	Configure(cfg)
	require.Nil(t, Current())

	cfg.SBOMStorage.Enabled = true
	Configure(cfg)
	first := Current()
	require.NotNil(t, first)
	Configure(cfg)
	require.Same(t, first, Current())

	cfg.SBOMStorage.Prefix = "other"
	Configure(cfg)
	require.NotNil(t, Current())
	require.NotSame(t, first, Current())

	cfg.SBOMStorage.Bucket = "X"
	Configure(cfg)
	require.Nil(t, Current())

	cfg.SBOMStorage.Enabled = false
	Configure(cfg)
	require.Nil(t, Current())
}
