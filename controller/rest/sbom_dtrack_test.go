package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

const dtURL = "/v1/sbom/dependency_track"

func dtSetup() {
	preTest()
	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	router.GET(dtURL, handlerDependencyTrackGet)
	router.PATCH(dtURL, handlerDependencyTrackConfig)
	access.AddRole("sbom-reader", &share.CLUSUserRoleInternal{ReadPermits: share.PERM_SBOM})
	access.AddRole("sbom-none", &share.CLUSUserRoleInternal{ReadPermits: share.PERM_REG_SCAN})
}

func dtPatch(role, cfg string) *mockResponseWriter {
	return restCall("PATCH", dtURL, []byte(`{"config":`+cfg+`}`), role)
}

func dtGet(t *testing.T) api.RESTDependencyTrack {
	w := restCall("GET", dtURL, nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Fatalf("GET status=%d", w.status)
	}
	var d api.RESTDependencyTrackData
	if err := json.Unmarshal(w.body, &d); err != nil || d.Config == nil {
		t.Fatalf("GET body=%s", w.body)
	}
	return *d.Config
}

func TestDependencyTrackDefaults(t *testing.T) {
	dtSetup()
	defer postTest()

	c := dtGet(t)
	if c.Enabled || c.URL != "" || c.APIKeySet || c.ProjectName == "" || c.ProjectVersion == "" || c.InactiveGrace != 1440 {
		t.Errorf("unexpected defaults: %+v", c)
	}
	w := restCall("GET", dtURL, nil, api.UserRoleAdmin)
	if !strings.Contains(string(w.body), `"tags":[]`) {
		t.Errorf("tags must be an empty array: %s", w.body)
	}
}

func TestDependencyTrackRoundTripNoKeyLeak(t *testing.T) {
	dtSetup()
	defer postTest()

	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	defer log.SetOutput(nil)
	defer log.SetLevel(log.FatalLevel)

	w := dtPatch(api.UserRoleAdmin, `{"enabled":true,"url":"https://dt.example.com:8081/","api_key":"  super-secret-key ","tags":["a","{namespace}"],"inactive_grace_period":60}`)
	if w.status != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%s", w.status, w.body)
	}
	c := dtGet(t)
	if !c.Enabled || c.URL != "https://dt.example.com:8081" || !c.APIKeySet || len(c.Tags) != 2 || c.InactiveGrace != 60 {
		t.Errorf("unexpected config: %+v", c)
	}
	if cc, _ := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl()); cc.DependencyTrack.APIKey != "super-secret-key" {
		t.Errorf("stored key not trimmed: %q", cc.DependencyTrack.APIKey)
	}
	if g := restCall("GET", dtURL, nil, api.UserRoleAdmin); strings.Contains(string(g.body), "super-secret-key") {
		t.Errorf("key in GET response: %s", g.body)
	}

	// a new URL needs the key again, so a stored key never goes to another server
	if w = dtPatch(api.UserRoleAdmin, `{"url":"http://other:8080"}`); w.status != http.StatusBadRequest {
		t.Fatalf("URL change without key: status=%d, want 400", w.status)
	}
	// nil keeps the key
	if w = dtPatch(api.UserRoleAdmin, `{"tags":[]}`); w.status != http.StatusOK {
		t.Fatalf("PATCH status=%d", w.status)
	}
	if c = dtGet(t); !c.APIKeySet || c.URL != "https://dt.example.com:8081" {
		t.Errorf("key must be kept: %+v", c)
	}
	// reject (invalid) requests that carry the key
	dtPatch(api.UserRoleAdmin, `{"api_key":"super-secret-key\u0001"}`)
	dtPatch(api.UserRoleAdmin, `{"api_key":"super-secret-key","project_name":"{bogus}"}`)
	// "" clears; enabled then needs a key (clearing the key of an enabled config is rejected)
	if w = dtPatch(api.UserRoleAdmin, `{"api_key":""}`); w.status != http.StatusBadRequest {
		t.Errorf("clear key while enabled: status=%d, want 400", w.status)
	}
	dtPatch(api.UserRoleAdmin, `{"enabled":false}`)
	if w = dtPatch(api.UserRoleAdmin, `{"api_key":""}`); w.status != http.StatusOK {
		t.Fatalf("PATCH status=%d", w.status)
	}
	if c = dtGet(t); c.APIKeySet {
		t.Errorf("key must be cleared: %+v", c)
	}
	if w = dtPatch(api.UserRoleAdmin, `{"enabled":true}`); w.status != http.StatusBadRequest {
		t.Errorf("enable without key: status=%d, want 400", w.status)
	}

	if strings.Contains(buf.String(), "super-secret-key") {
		t.Errorf("API key found in log output: %s", buf.String())
	}
}

func TestDependencyTrackInvalid(t *testing.T) {
	dtSetup()
	defer postTest()

	for _, body := range []string{
		`{"url":"ftp://h"}`, `{"url":"file:///etc/passwd"}`, `{"url":"https://"}`, `{"url":"/relative"}`,
		`{"url":"https://u:p@h"}`, `{"url":"https://h/?a=b"}`, `{"url":"https://h/#x"}`,
		`{"enabled":true,"api_key":"k"}`, `{"enabled":true,"url":"https://h"}`,
		`{"project_name":"{foo}"}`, `{"project_version":"{cluster"}`, `{"tags":["a,b"]}`,
		`{"inactive_grace_period":525601}`,
	} {
		if w := dtPatch(api.UserRoleAdmin, body); w.status != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", body, w.status)
		}
	}
	if w := restCall("PATCH", dtURL, []byte(`{bad`), api.UserRoleAdmin); w.status != http.StatusBadRequest {
		t.Errorf("bad json: status=%d", w.status)
	}
	if w := restCall("PATCH", dtURL, []byte(`{}`), api.UserRoleAdmin); w.status != http.StatusBadRequest {
		t.Errorf("nil config: status=%d", w.status)
	}
	if c := dtGet(t); c.URL != "" || c.Enabled {
		t.Errorf("config changed by invalid requests: %+v", c)
	}
	if w := dtPatch(api.UserRoleAdmin, `{"url":"https://h","inactive_grace_period":525600}`); w.status != http.StatusOK {
		t.Errorf("valid: status=%d", w.status)
	}
}

func TestDependencyTrackPermissions(t *testing.T) {
	dtSetup()
	defer postTest()

	body := `{"url":"https://h"}`
	for _, role := range []string{"sbom-none", api.UserRoleCIOps} {
		if w := restCall("GET", dtURL, nil, role); w.status != http.StatusForbidden {
			t.Errorf("%s GET: status=%d, want 403", role, w.status)
		}
		if w := dtPatch(role, body); w.status != http.StatusForbidden {
			t.Errorf("%s PATCH: status=%d, want 403", role, w.status)
		}
	}
	// reader: read only
	if w := restCall("GET", dtURL, nil, api.UserRoleReader); w.status != http.StatusOK {
		t.Errorf("reader GET: status=%d", w.status)
	}
	if w := dtPatch(api.UserRoleReader, body); w.status != http.StatusForbidden {
		t.Errorf("reader PATCH: status=%d, want 403", w.status)
	}
	// namespace-only users: the setting is global
	roles := map[string][]string{"sbom-reader": {"ns1"}}
	if w := restCallWithRole("GET", dtURL, nil, api.UserRoleNone, roles); w.status != http.StatusForbidden {
		t.Errorf("namespace user GET: status=%d, want 403", w.status)
	}
	if w := restCallWithRole("PATCH", dtURL, []byte(`{"config":`+body+`}`), api.UserRoleNone, roles); w.status != http.StatusForbidden {
		t.Errorf("namespace user PATCH: status=%d, want 403", w.status)
	}
}
