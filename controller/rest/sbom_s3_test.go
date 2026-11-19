package rest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/controller/sbom/s3store/s3fake"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
)

const (
	s3TestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	s3TestSecret = "s3cr3t-value-xyz"
	s3TestDoc    = `{"bomFormat":"CycloneDX","marker":"from-s3"}`
)

type sbomS3MockScan struct {
	sbomMockScan
}

func (m *sbomS3MockScan) GetRegistryImageModules(name, id string, acc *access.AccessControl) ([]*share.ScanModule, *share.CLUSRegistryImageSummary, error) {
	modules, sum, err := m.sbomMockScan.GetRegistryImageModules(name, id, acc)
	if sum != nil {
		sum.Digest, sum.RegName, sum.ImageID = s3TestDigest, "reg1", id // the only mock registry, also for "all"
	}
	return modules, sum, err
}

func (m *sbomS3MockScan) GetRegistryImagesByDigest(digests map[string]bool, acc *access.AccessControl) []scan.RegistryImageRef {
	refs := []scan.RegistryImageRef{}
	if digests[s3TestDigest] && acc.Authorize(&share.CLUSRegistryConfig{Name: "reg1", Domains: []string{"ns1"}}, nil) {
		refs = append(refs, scan.RegistryImageRef{Registry: "reg1", ImageID: "img1", Digest: s3TestDigest, Images: []string{"lib/app:1.0"}})
	}
	return refs
}

// sbomS3Setup returns the fake S3 server; the store is enabled and holds the document of the test digest.
func sbomS3Setup(t *testing.T) *s3fake.Server {
	sbomSetup()
	scanner = &sbomS3MockScan{}
	router.PATCH("/v1/sbom/s3", handlerSBOMStorageConfig)
	router.GET("/v1/sbom/s3", handlerSBOMStorageGet)
	router.GET("/v1/sbom/s3/images", handlerSBOMStorageImages)
	access.AddRole("sbom-writer", &share.CLUSUserRoleInternal{ReadPermits: share.PERM_SBOM, WritePermits: share.PERM_SBOM})

	srv := s3fake.New()
	t.Cleanup(func() {
		s3store.Configure(&share.CLUSSystemConfig{})
		srv.Close()
		postTest()
	})
	cfg := &share.CLUSSystemConfig{ClusterName: "cluster1", SBOMStorage: share.CLUSSBOMStorage{
		Enabled: true, Endpoint: srv.URL, Bucket: "bucket", PathStyle: true, AccessKey: "ak", SecretKey: s3TestSecret,
	}}
	s3store.Configure(cfg)
	clusHelper.PutSystemConfigRev(cfg, 0)
	return srv
}

func sbomS3Put(t *testing.T, doc string) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(doc))
	zw.Close()
	st := s3store.Current()
	if st == nil {
		t.Fatal("store is disabled")
	}
	if err := st.Put(t.Context(), s3TestDigest, "reg1", "img1", buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func sbomS3Call(method, url, body, role string, roleDomains map[string][]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest(method, url, strings.NewReader(body))
	login := mockLoginUser("sbomuser", role, api.FedRoleNone, roleDomains)
	r.Header.Add(api.RESTTokenHeader, login.token)
	router.ServeHTTP(w, r)
	newJWTExpireSession()
	login._logout()
	return w
}

func TestSBOMStorageGet(t *testing.T) {
	sbomS3Setup(t)

	if c := sbomS3Call("GET", "/v1/sbom/s3", "", "sbom-no-perm", nil).Code; c != http.StatusForbidden {
		t.Errorf("no sbom: status=%d, want 403", c)
	}
	ns := map[string][]string{"sbom-reader": {"ns1"}}
	if c := sbomS3Call("GET", "/v1/sbom/s3", "", api.UserRoleNone, ns).Code; c != http.StatusForbidden {
		t.Errorf("namespace-only sbom: status=%d, want 403", c)
	}
	w := sbomS3Call("GET", "/v1/sbom/s3", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin: status=%d, want 200", w.Code)
	}
	var resp api.RESTSBOMStorageData
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Config == nil {
		t.Fatalf("bad body: %v %s", err, w.Body.String())
	}
	if !resp.Config.SecretKeySet || resp.Config.AccessKey != "ak" || resp.Config.DeleteGrace != s3store.DefaultGraceMinutes {
		t.Errorf("unexpected config: %+v", resp.Config)
	}
	if strings.Contains(w.Body.String(), s3TestSecret) {
		t.Errorf("secret key in the response: %s", w.Body.String())
	}
}

func TestSBOMStoragePatch(t *testing.T) {
	sbomS3Setup(t)

	var logs bytes.Buffer
	oldOut, oldLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&logs)
	log.SetLevel(log.DebugLevel)
	defer func() { log.SetOutput(oldOut); log.SetLevel(oldLevel) }()

	patch := func(body, role string) int { return sbomS3Call("PATCH", "/v1/sbom/s3", body, role, nil).Code }
	stored := func() share.CLUSSBOMStorage {
		c, _ := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl())
		return c.SBOMStorage
	}

	if c := patch(`{"config":{"bucket":"abc"}}`, api.UserRoleReader); c != http.StatusForbidden {
		t.Errorf("reader: status=%d, want 403", c)
	}
	bad := []string{
		`{"config":{"endpoint":"ftp://x"}}`,
		`{"config":{"endpoint":"http://u:p@x"}}`,
		`{"config":{"endpoint":"http://x/path"}}`,
		`{"config":{"endpoint":"http://x?a=1"}}`,
		`{"config":{"bucket":"Bad_Bucket"}}`,
		`{"config":{"secret_key":"","access_key":"ak"}}`,
		`{"config":{"secret_key":" pad "}}`,
		`{"config":{"delete_grace_period":999999999}}`,
		`{"config":{"endpoint":"http://other.example"}}`, // stored secret, no secret_key
		`{}`,
	}
	for _, b := range bad {
		if c := patch(b, api.UserRoleAdmin); c != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", b, c)
		}
	}
	if got := stored(); got.SecretKey != s3TestSecret || got.Bucket != "bucket" {
		t.Errorf("rejected requests changed the config: %+v", got)
	}

	if c := patch(`{"config":{"endpoint":" http://other.example/ ","secret_key":"newsecret","access_key":" ak2 ","region":"eu-west-1","delete_unused":true,"delete_grace_period":60}}`, "sbom-writer"); c != http.StatusOK {
		t.Fatalf("endpoint change with secret: status=%d, want 200", c)
	}
	got := stored()
	want := share.CLUSSBOMStorage{Enabled: true, Endpoint: "http://other.example", Region: "eu-west-1", Bucket: "bucket", PathStyle: true,
		AccessKey: "ak2", SecretKey: "newsecret", DeleteUnused: true, DeleteGrace: 60}
	if got != want {
		t.Errorf("stored=%+v, want %+v", got, want)
	}

	if c := patch(`{"config":{"secret_key":"","access_key":""}}`, api.UserRoleAdmin); c != http.StatusOK {
		t.Fatalf("default credential chain: status=%d, want 200", c)
	}
	if got := stored(); got.SecretKey != "" || got.AccessKey != "" || got.Endpoint != "http://other.example" {
		t.Errorf("stored=%+v", got)
	}

	if strings.Contains(logs.String(), s3TestSecret) || strings.Contains(logs.String(), "newsecret") {
		t.Errorf("secret in the log output: %s", logs.String())
	}
}

func TestSBOMStorageDownload(t *testing.T) {
	srv := sbomS3Setup(t)
	const regURL = "/v1/scan/registry/reg1/image/img1/sbom"
	cdx := "application/vnd.cyclonedx+json"

	// no object: the inventory document
	w := sbomS3Call("GET", regURL, "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "registrymod") {
		t.Fatalf("no object: status=%d body=%s", w.Code, w.Body.String())
	}

	sbomS3Put(t, s3TestDoc)
	for _, url := range []string{regURL, "/v1/scan/image/img1/sbom"} {
		cacher = &sbomMockCache{wlImageID: "img1"}
		w = sbomS3Call("GET", url, "", api.UserRoleAdmin, nil)
		if w.Code != http.StatusOK || w.Body.String() != s3TestDoc || w.Header().Get("Content-Type") != cdx {
			t.Errorf("%s: status=%d type=%q body=%s", url, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
	}

	// the same digest written by the scan of another registry image: never served (cross-tenant)
	if err := s3store.Current().Put(t.Context(), s3TestDigest, "reg-other", "img1", []byte{0x1f, 0x8b}); err != nil {
		t.Fatal(err)
	}
	w = sbomS3Call("GET", regURL, "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "from-s3") || !strings.Contains(w.Body.String(), "registrymod") {
		t.Errorf("other owner: status=%d body=%s", w.Code, w.Body.String())
	}
	sbomS3Put(t, s3TestDoc)

	// the workload endpoint and SPDX always use the inventory
	w = sbomS3Call("GET", "/v1/scan/workload/wl1/sbom", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "from-s3") {
		t.Errorf("workload: status=%d body=%s", w.Code, w.Body.String())
	}
	w = sbomS3Call("GET", regURL+"?format=spdx", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "from-s3") || !strings.Contains(w.Body.String(), "registrymod") {
		t.Errorf("spdx: status=%d body=%s", w.Code, w.Body.String())
	}

	// S3 failure: the inventory document
	srv.SetFail(true)
	w = sbomS3Call("GET", regURL, "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "registrymod") {
		t.Errorf("S3 failing: status=%d body=%s", w.Code, w.Body.String())
	}
	srv.SetFail(false)

	// damaged object (cut gzip stream): the inventory document, never a cut 200 body
	for key, b := range srv.Objects() {
		srv.Put(key, b[:len(b)-6])
	}
	w = sbomS3Call("GET", regURL, "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "registrymod") {
		t.Errorf("damaged object: status=%d body=%s", w.Code, w.Body.String())
	}

	// no access to the registry: 403 and no S3 request
	before := srv.Requests()
	other := map[string][]string{"sbom-reader": {"ns2"}}
	if c := sbomS3Call("GET", regURL, "", api.UserRoleNone, other).Code; c != http.StatusForbidden {
		t.Errorf("other namespace: status=%d, want 403", c)
	}
	if n := srv.Requests(); n != before {
		t.Errorf("S3 got %d requests for a denied user", n-before)
	}
}

func TestSBOMStorageImages(t *testing.T) {
	srv := sbomS3Setup(t)
	sbomS3Put(t, s3TestDoc)
	srv.Put("other/images/"+s3TestDigest+".cdx.json.gz", []byte("x")) // foreign cluster
	srv.Put("cluster1/images/junk.cdx.json.gz", []byte("x"))          // invalid digest

	var resp api.RESTSBOMStorageImagesData
	w := sbomS3Call("GET", "/v1/sbom/s3/images", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Images) != 1 {
		t.Fatalf("admin: status=%d body=%s", w.Code, w.Body.String())
	}
	if e := resp.Images[0]; e.Registry != "reg1" || e.ImageID != "img1" || e.Digest != s3TestDigest || e.Size == 0 || e.LastModified == "" || len(e.Images) != 1 {
		t.Errorf("unexpected entry: %+v", e)
	}

	w = sbomS3Call("GET", "/v1/sbom/s3/images", "", api.UserRoleNone, map[string][]string{"sbom-reader": {"ns2"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"images":[]`) {
		t.Errorf("other namespace: status=%d body=%s", w.Code, w.Body.String())
	}
	if c := sbomS3Call("GET", "/v1/sbom/s3/images", "", "sbom-no-perm", nil).Code; c != http.StatusForbidden {
		t.Errorf("no sbom: status=%d, want 403", c)
	}

	// the object of the digest belongs to another registry image: not listed
	if err := s3store.Current().Put(t.Context(), s3TestDigest, "reg-other", "img9", []byte("x")); err != nil {
		t.Fatal(err)
	}
	w = sbomS3Call("GET", "/v1/sbom/s3/images", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"images":[]`) {
		t.Errorf("other owner: status=%d body=%s", w.Code, w.Body.String())
	}

	srv.SetFail(true)
	w = sbomS3Call("GET", "/v1/sbom/s3/images", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("S3 failing: status=%d, want 500", w.Code)
	}
	srv.SetFail(false)

	s3store.Configure(&share.CLUSSystemConfig{})
	w = sbomS3Call("GET", "/v1/sbom/s3/images", "", api.UserRoleAdmin, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"images":[]`) {
		t.Errorf("disabled: status=%d body=%s", w.Code, w.Body.String())
	}
}
