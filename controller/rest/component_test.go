package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

const log4jPurl = "pkg:maven/org.apache.logging.log4j/log4j-core@"

func log4j(ver string) *share.ScanModule {
	return &share.ScanModule{Name: "org.apache.logging.log4j:log4j-core", Version: ver, Purl: log4jPurl + ver}
}

type componentMockCache struct {
	mockCache
	modules map[string][]*share.ScanModule
}

func (m *componentMockCache) GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief {
	var list []*api.RESTWorkloadBrief
	for _, wl := range []*api.RESTWorkloadBrief{
		{ID: "wl1", Name: "wl1", PodName: "pod1", Domain: "ns1", Image: "app:1", ImageID: "img1"},
		{ID: "wl1b", Name: "wl1b", Domain: "ns1", Image: "app:1", ImageID: "img1"},
		{ID: "wl2", Name: "wl2", Domain: "ns2", Image: "app:2", ImageID: "img2"},
		{ID: "wlx", Name: "wlx", Domain: "ns1", Image: "app:1", ImageID: "img1", State: api.WorkloadStateExit},
	} {
		if acc.Authorize(&share.CLUSWorkload{Domain: wl.Domain}, nil) {
			list = append(list, wl)
		}
	}
	return list
}

func (m *componentMockCache) GetAllHosts(acc *access.AccessControl) []*api.RESTHost {
	if !acc.Authorize(&share.CLUSHost{}, nil) {
		return nil
	}
	return []*api.RESTHost{{ID: "h1", Name: "host1"}}
}

func (m *componentMockCache) GetScanModules(id string) ([]*share.ScanModule, string, error) {
	mods, ok := m.modules[id]
	if !ok {
		return nil, "", common.ErrObjectNotFound
	}
	return mods, "debian:12", nil
}

type componentMockScan struct {
	sbomMockScan
	modules map[string][]*share.ScanModule // by image ID
}

var componentRegistries = map[string]string{"reg1": "ns1", "reg2": "ns2"}

func (m *componentMockScan) authorized(name string, acc *access.AccessControl) bool {
	d, ok := componentRegistries[name]
	return ok && acc.Authorize(&share.CLUSRegistryConfig{Name: name, Domains: []string{d}}, nil)
}

func (m *componentMockScan) GetAllRegistrySummary(scope string, acc *access.AccessControl) []*api.RESTRegistrySummary {
	var list []*api.RESTRegistrySummary
	for _, n := range []string{"reg1", "reg2"} {
		if m.authorized(n, acc) {
			list = append(list, &api.RESTRegistrySummary{RESTRegistry: api.RESTRegistry{Name: n}})
		}
	}
	return list
}

func (m *componentMockScan) GetRegistryImageSummary(name string, vpf scanUtils.VPFInterface, acc *access.AccessControl) []*api.RESTRegistryImageSummary {
	if !m.authorized(name, acc) {
		return nil
	}
	id := map[string]string{"reg1": "ri1", "reg2": "ri2"}[name]
	return []*api.RESTRegistryImageSummary{
		{ImageID: id, Digest: "sha256:" + id, Repository: "lib/app", Tag: "2.0", Domain: componentRegistries[name]},
		{ImageID: id, Digest: "sha256:" + id, Repository: "lib/app", Tag: "1.0", Domain: componentRegistries[name]},
	}
}

func (m *componentMockScan) GetRegistryImageModules(name, id string, acc *access.AccessControl) ([]*share.ScanModule, *share.CLUSRegistryImageSummary, error) {
	if !m.authorized(name, acc) {
		return nil, nil, common.ErrObjectAccessDenied
	}
	mods, ok := m.modules[id]
	if !ok {
		return nil, nil, common.ErrObjectNotFound
	}
	return mods, &share.CLUSRegistryImageSummary{BaseOS: "debian:12"}, nil
}

func componentSetup(t *testing.T) {
	sbomSetup()
	// the roles of sbomSetup would break the role tests that run later
	t.Cleanup(func() { access.DeleteRole("sbom-no-perm"); access.DeleteRole("sbom-reader") })
	cacher = &componentMockCache{modules: map[string][]*share.ScanModule{
		"wl1":  {log4j("2.14.1"), {Name: "openssl", Version: "3.0.1-1", Source: "debian:12"}},
		"wl1b": {log4j("2.14.1")},
		"wl2":  {log4j("2.17.1")},
		"wlx":  {log4j("2.14.1")},
		"h1":   {log4j("2.12.0")},
	}}
	scanner = &componentMockScan{modules: map[string][]*share.ScanModule{
		"ri1": {log4j("2.15.0")},
		"ri2": {log4j("2.17.1")},
	}}
	router.GET("/v1/scan/component", handlerScanComponent)
}

func componentCall(t *testing.T, query, role string, domains map[string][]string) (int, *api.RESTComponentSearchData) {
	t.Helper()
	w := sbomCall("/v1/scan/component?"+query, role, domains)
	var d api.RESTComponentSearchData
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatalf("%s: %v: %s", query, err, w.Body.String())
		}
		for _, l := range []bool{d.Workloads == nil, d.Hosts == nil, d.Images == nil, d.RunningImages == nil} {
			if l {
				t.Errorf("%s: a list is null: %s", query, w.Body.String())
			}
		}
	}
	return w.Code, &d
}

func TestComponentAdmin(t *testing.T) {
	componentSetup(t)
	defer postTest()

	code, d := componentCall(t, "name=log4j-core", api.UserRoleAdmin, nil)
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if len(d.Workloads) != 3 || d.Workloads[0].Name != "pod1" || d.Workloads[1].ID != "wl1b" || d.Workloads[2].ID != "wl2" {
		t.Errorf("workloads (sorted by domain, name, id; exited skipped): %+v", d.Workloads)
	}
	if len(d.Hosts) != 1 || d.Hosts[0].Name != "host1" {
		t.Errorf("hosts: %+v", d.Hosts)
	}
	if len(d.Images) != 2 || d.Images[0].Registry != "reg1" || strings.Join(d.Images[0].Images, ",") != "lib/app:1.0,lib/app:2.0" || d.Images[0].Domain != "ns1" {
		t.Errorf("images: %+v", d.Images)
	}
	if len(d.RunningImages) != 2 || d.RunningImages[0].ImageID != "img1" || d.RunningImages[0].Workloads != 2 || len(d.RunningImages[0].Components) != 1 {
		t.Errorf("running images: %+v", d.RunningImages)
	}
}

func TestComponentNamespaceUser(t *testing.T) {
	componentSetup(t)
	defer postTest()

	code, d := componentCall(t, "name=log4j-core", api.UserRoleNone, map[string][]string{"sbom-reader": {"ns1"}})
	if code != http.StatusOK {
		t.Fatalf("status=%d", code)
	}
	if len(d.Workloads) != 2 || d.Workloads[0].Domain != "ns1" || d.Workloads[1].Domain != "ns1" {
		t.Errorf("workloads: %+v", d.Workloads)
	}
	if len(d.Hosts) != 0 {
		t.Errorf("a namespace user must not see hosts: %+v", d.Hosts)
	}
	if len(d.Images) != 1 || d.Images[0].Registry != "reg1" {
		t.Errorf("images: %+v", d.Images)
	}
}

func TestComponentNoPermission(t *testing.T) {
	componentSetup(t)
	defer postTest()

	for _, role := range []string{"sbom-no-perm", api.UserRoleCIOps} {
		if c, _ := componentCall(t, "name=log4j-core", role, nil); c != http.StatusForbidden {
			t.Errorf("%s: status=%d, want 403", role, c)
		}
	}
}

func TestComponentMatch(t *testing.T) {
	componentSetup(t)
	defer postTest()

	cases := []struct {
		query     string
		workloads int // admin: wl1, wl1b (2.14.1), wl2 (2.17.1)
	}{
		{"name=LOG4J-CORE", 3},
		{"name=org.apache.logging.log4j:log4j-core", 3},
		{"name=log4j", 0},
		{"name=openssl", 1},
		{"purl=" + log4jPurl + "2.14.1", 2},
		{"purl=" + log4jPurl, 3},
		{"purl=pkg:maven/org.apache.logging.log4j/log4j-api", 0},
		{"name=log4j-core&version=2.17.1", 1},
		{"name=log4j-core&version=%3C2.17.1", 2},
		{"name=log4j-core&version=%3E%3D2.14.1,%20%3C2.17.1", 2},
		{"name=log4j-core&version=%3E2.17.1", 0},
		{"purl=" + log4jPurl + "&version=%3C2.15", 2},
		{"name=other&purl=" + log4jPurl, 0},
	}
	for _, c := range cases {
		code, d := componentCall(t, c.query, api.UserRoleAdmin, nil)
		if code != http.StatusOK || len(d.Workloads) != c.workloads {
			t.Errorf("%s: status=%d workloads=%d, want %d", c.query, code, len(d.Workloads), c.workloads)
		}
	}
}

func TestComponentBadRequest(t *testing.T) {
	componentSetup(t)
	defer postTest()

	for _, q := range []string{
		"", "version=1.0", "purl=notapurl", "name=a&version=", "name=a&version=%3C", "name=a&version=~1.0",
		"name=" + strings.Repeat("a", 257), "purl=pkg:maven/a/" + strings.Repeat("b", 512),
		"name=a&version=" + strings.Repeat("1", 129),
	} {
		if q == "name=a&version=" { // an empty optional parameter is the same as none
			if c, _ := componentCall(t, q, api.UserRoleAdmin, nil); c != http.StatusOK {
				t.Errorf("%q: status=%d, want 200", q, c)
			}
			continue
		}
		if c, _ := componentCall(t, q, api.UserRoleAdmin, nil); c != http.StatusBadRequest {
			t.Errorf("%q: status=%d, want 400", q, c)
		}
	}
}

func TestComponentBusy(t *testing.T) {
	componentSetup(t)
	defer postTest()

	componentSearchLock.Lock()
	c, _ := componentCall(t, "name=log4j-core", api.UserRoleAdmin, nil)
	componentSearchLock.Unlock()
	if c != http.StatusTooManyRequests {
		t.Errorf("status=%d, want 429", c)
	}
}

// TestComponentSearchPerf measures one search over 2000 workloads with 500 modules each in the real SQLite db.
func TestComponentSearchPerf(t *testing.T) {
	if os.Getenv("NV_COMPONENT_PERF") != "1" {
		t.Skip("set NV_COMPONENT_PERF=1")
	}
	const workloads, modulesPerWL = 2000, 500
	if err := db.CreateVulAssetDb(false); err != nil {
		t.Fatal(err)
	}
	defer os.Remove("/tmp/vulasset.db")

	for i := 0; i < workloads; i++ {
		mods := make([]*share.ScanModule, 0, modulesPerWL)
		for j := 0; j < modulesPerWL; j++ {
			switch j % 3 {
			case 0:
				mods = append(mods, &share.ScanModule{Name: fmt.Sprintf("pkg%d", j), Version: fmt.Sprintf("1.%d-%d", j, i%7), Source: "debian:12"})
			case 1:
				mods = append(mods, &share.ScanModule{Name: fmt.Sprintf("com.example:lib%d", j), Version: fmt.Sprintf("2.%d.%d", j, i%5),
					Purl: fmt.Sprintf("pkg:maven/com.example/lib%d@2.%d.%d", j, j, i%5), File: fmt.Sprintf("/app/lib%d.jar", j)})
			default:
				mods = append(mods, &share.ScanModule{Name: fmt.Sprintf("npm%d", j), Version: fmt.Sprintf("3.%d.%d", j, i%5),
					Purl: fmt.Sprintf("pkg:npm/npm%d@3.%d.%d", j, j, i%5)})
			}
		}
		if i%10 == 0 {
			mods[1] = log4j("2.14.1")
		}
		if err := db.PopulateAssetVul(&db.DbAssetVul{Type: db.AssetWorkload, AssetID: fmt.Sprintf("wl%d", i), Name: fmt.Sprintf("wl%d", i), Modules: mods}); err != nil {
			t.Fatal(err)
		}
	}

	componentSetup(t)
	cacher = &perfMockCache{n: workloads}

	start := time.Now()
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/v1/scan/component?name=log4j-core&version=%3C2.17.1", bytes.NewBuffer(nil))
	login := mockLoginUser("sbomuser", api.UserRoleAdmin, api.FedRoleNone, nil)
	r.Header.Add(api.RESTTokenHeader, login.token)
	router.ServeHTTP(w, r)
	t.Logf("search over %d workloads x %d modules: %v (status %d, %d bytes)", workloads, modulesPerWL, time.Since(start), w.Code, w.Body.Len())
	login._logout()
	postTest()
}

type perfMockCache struct {
	mockCache
	n int
}

func (m *perfMockCache) GetAllWorkloadsBrief(view string, acc *access.AccessControl) []*api.RESTWorkloadBrief {
	list := make([]*api.RESTWorkloadBrief, m.n)
	for i := range list {
		list[i] = &api.RESTWorkloadBrief{ID: fmt.Sprintf("wl%d", i), Name: fmt.Sprintf("wl%d", i), Domain: "ns1", ImageID: fmt.Sprintf("img%d", i%50)}
	}
	return list
}

func (m *perfMockCache) GetAllHosts(acc *access.AccessControl) []*api.RESTHost { return nil }

func (m *perfMockCache) GetScanModules(id string) ([]*share.ScanModule, string, error) {
	modules, err := db.GetModules(id)
	return modules, "debian:12", err
}
