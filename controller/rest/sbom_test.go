package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
)

type sbomMockCache struct {
	mockCache
}

func (m *sbomMockCache) GetWorkload(id, view string, acc *access.AccessControl) (*api.RESTWorkload, error) {
	var domain string
	switch id {
	case "wl1":
		domain = "ns1"
	case "wl2":
		domain = "ns2"
	default:
		return nil, common.ErrObjectNotFound
	}
	if !acc.Authorize(&share.CLUSWorkload{Domain: domain}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return &api.RESTWorkload{RESTWorkloadBrief: api.RESTWorkloadBrief{ID: id, Name: id, Domain: domain}}, nil
}

func (m *sbomMockCache) GetHost(id string, acc *access.AccessControl) (*api.RESTHost, error) {
	if id != "h1" {
		return nil, common.ErrObjectNotFound
	}
	if !acc.Authorize(&share.CLUSHost{}, nil) {
		return nil, common.ErrObjectAccessDenied
	}
	return &api.RESTHost{ID: id, Name: "host1"}, nil
}

func (m *sbomMockCache) GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief {
	return []*api.RESTWorkloadBrief{{ID: "wl1", ImageID: "img1", Domain: "ns1",
		ScanSummary: &api.RESTScanBrief{Status: api.ScanStatusFinished}}}
}

func (m *sbomMockCache) GetScanModules(id string) ([]*share.ScanModule, string, error) {
	return []*share.ScanModule{{Name: "m", Version: "1"}}, "debian:12", nil
}

func (m *sbomMockCache) GetSystemConfigClusterName(acc *access.AccessControl) string {
	return "cluster1"
}

type sbomMockScan struct {
	scan.ScanInterface
}

func (m *sbomMockScan) GetRegistryImageModules(name, id string, acc *access.AccessControl) ([]*share.ScanModule, *share.CLUSRegistryImageSummary, error) {
	// registry "reg1" is visible to namespace ns1 only
	if !acc.Authorize(&share.CLUSRegistryConfig{Name: name, Domains: []string{"ns1"}}, nil) {
		return nil, nil, common.ErrObjectAccessDenied
	}
	if id != "img1" {
		return nil, nil, common.ErrObjectNotFound
	}
	return []*share.ScanModule{{Name: "m", Version: "1"}}, &share.CLUSRegistryImageSummary{
		BaseOS: "debian:12", Digest: "sha256:abc", Images: []share.CLUSImage{{Repo: "lib/app", Tag: "1.0"}},
	}, nil
}

func sbomCall(url, role string, roleDomains map[string][]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", url, bytes.NewBuffer(nil))
	login := mockLoginUser("sbomuser", role, api.FedRoleNone, roleDomains)
	r.Header.Add(api.RESTTokenHeader, login.token)
	router.ServeHTTP(w, r)
	newJWTExpireSession()
	login._logout()
	return w
}

func sbomSetup() {
	preTest()
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &sbomMockCache{}
	scanner = &sbomMockScan{}

	router.GET("/v1/scan/workload/:id/sbom", handlerScanWorkloadSBOM)
	router.GET("/v1/scan/image/:id/sbom", handlerScanImageSBOM)
	router.GET("/v1/scan/host/:id/sbom", handlerScanHostSBOM)
	router.GET("/v1/scan/registry/:name/image/:id/sbom", handlerRegistryImageSBOM)

	access.AddRole("sbom-no-perm", &share.CLUSUserRoleInternal{
		ReadPermits: share.PERMS_RUNTIME_SCAN | share.PERM_REG_SCAN,
	})
	access.AddRole("sbom-reader", &share.CLUSUserRoleInternal{ReadPermits: share.PERM_SBOM})
}

var sbomURLs = []string{
	"/v1/scan/workload/wl1/sbom",
	"/v1/scan/image/img1/sbom",
	"/v1/scan/host/h1/sbom",
	"/v1/scan/registry/reg1/image/img1/sbom",
}

func TestSBOMNoPermission(t *testing.T) {
	sbomSetup()
	defer postTest()

	for _, url := range sbomURLs {
		if w := sbomCall(url, "sbom-no-perm", nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: custom role without sbom: status=%d, want 403", url, w.Code)
		}
		if w := sbomCall(url, api.UserRoleCIOps, nil); w.Code != http.StatusForbidden {
			t.Errorf("%s: ciops: status=%d, want 403", url, w.Code)
		}
	}
}

func TestSBOMReservedRoles(t *testing.T) {
	sbomSetup()
	defer postTest()

	for _, role := range []string{api.UserRoleAdmin, api.UserRoleReader} {
		for _, url := range sbomURLs {
			w := sbomCall(url, role, nil)
			if w.Code != http.StatusOK {
				t.Errorf("%s: %s: status=%d, want 200", url, role, w.Code)
			}
		}
	}
}

func TestSBOMNamespaceUser(t *testing.T) {
	sbomSetup()
	defer postTest()

	roles := map[string][]string{"sbom-reader": {"ns1"}}
	call := func(url string) int { return sbomCall(url, api.UserRoleNone, roles).Code }

	if c := call("/v1/scan/workload/wl1/sbom"); c != http.StatusOK {
		t.Errorf("workload in ns1: status=%d, want 200", c)
	}
	if c := call("/v1/scan/workload/wl2/sbom"); c != http.StatusForbidden {
		t.Errorf("workload in ns2: status=%d, want 403", c)
	}
	if c := call("/v1/scan/workload/nonexistent/sbom"); c != http.StatusNotFound {
		t.Errorf("unknown workload: status=%d, want 404", c)
	}
	if c := call("/v1/scan/host/h1/sbom"); c != http.StatusForbidden {
		t.Errorf("host (global object): status=%d, want 403", c)
	}
	if c := call("/v1/scan/registry/reg1/image/img1/sbom"); c != http.StatusOK {
		t.Errorf("registry visible to ns1: status=%d, want 200", c)
	}
	// the mock registry is only visible to ns1; a namespace user of ns2 must not get it
	other := map[string][]string{"sbom-reader": {"ns2"}}
	if c := sbomCall("/v1/scan/registry/reg1/image/img1/sbom", api.UserRoleNone, other).Code; c != http.StatusForbidden {
		t.Errorf("registry not visible to ns2: status=%d, want 403", c)
	}

	// sbom must be granted in the object's namespace: rt_scan in ns1 and sbom in ns2 do not give the ns1 SBOM
	mixed := map[string][]string{"sbom-no-perm": {"ns1"}, "sbom-reader": {"ns2"}}
	if c := sbomCall("/v1/scan/workload/wl1/sbom", api.UserRoleNone, mixed).Code; c != http.StatusForbidden {
		t.Errorf("workload in ns1 with sbom only in ns2: status=%d, want 403", c)
	}
	if c := sbomCall("/v1/scan/workload/wl2/sbom", api.UserRoleNone, mixed).Code; c != http.StatusOK {
		t.Errorf("workload in ns2 with sbom in ns2: status=%d, want 200", c)
	}
}

func TestSBOMFormat(t *testing.T) {
	sbomSetup()
	defer postTest()

	for _, url := range sbomURLs {
		cases := []struct {
			query string
			code  int
			ct    string
		}{
			{"", http.StatusOK, "application/vnd.cyclonedx+json"},
			{"?format=cyclonedx", http.StatusOK, "application/vnd.cyclonedx+json"},
			{"?format=spdx", http.StatusOK, "application/spdx+json"},
			{"?format=xml", http.StatusBadRequest, ""},
		}
		for _, c := range cases {
			w := sbomCall(url+c.query, api.UserRoleAdmin, nil)
			if w.Code != c.code {
				t.Errorf("%s%s: status=%d, want %d", url, c.query, w.Code, c.code)
				continue
			}
			if c.ct != "" {
				if got := w.Header().Get("Content-Type"); got != c.ct {
					t.Errorf("%s%s: Content-Type=%q, want %q", url, c.query, got, c.ct)
				}
				if got := w.Header().Get("Content-Disposition"); got != `attachment; filename="sbom.cdx.json"` && got != `attachment; filename="sbom.spdx.json"` {
					t.Errorf("%s%s: Content-Disposition=%q", url, c.query, got)
				}
			}
		}
	}

	// an unauthorized user gets 403 before the format is looked at
	if w := sbomCall(sbomURLs[0]+"?format=xml", "sbom-no-perm", nil); w.Code != http.StatusForbidden {
		t.Errorf("unauthorized user with bad format: status=%d, want 403", w.Code)
	}
}
