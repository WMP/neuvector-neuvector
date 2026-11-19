package cache

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

const dtrackTestKey = "SECRET-API-KEY-123"

type dtrackUpload struct{ name, version, tags string }

type fakeDTrack struct {
	*httptest.Server
	mu      sync.Mutex
	uploads []dtrackUpload
	patches []string
}

func newFakeDTrack(t *testing.T) *fakeDTrack {
	f := &fakeDTrack{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/bom":
			if r.ParseMultipartForm(1<<20) != nil {
				w.WriteHeader(400)
				return
			}
			v := r.MultipartForm.Value
			f.uploads = append(f.uploads, dtrackUpload{strings.Join(v["projectName"], ""), strings.Join(v["projectVersion"], ""), strings.Join(v["projectTags"], "")})
			io.WriteString(w, `{"token":"t"}`)
		case r.URL.Path == "/api/v1/project/lookup":
			json.NewEncoder(w).Encode(map[string]any{"uuid": "u-1", "active": true})
		case r.Method == http.MethodPatch:
			b, _ := io.ReadAll(r.Body)
			f.patches = append(f.patches, string(b))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeDTrack) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads), len(f.patches)
}

func (f *fakeDTrack) waitUploads(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if u, _ := f.counts(); u >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	u, _ := f.counts()
	t.Fatalf("want %d uploads, got %d", n, u)
}

type lockedBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// dtrackEnv isolates the global state and returns the captured log.
func dtrackEnv(t *testing.T) *lockedBuf {
	preTest()
	oldWl, oldScan, oldPods := wlCacheMap, scanMap, dtrackPods
	oldLeader, oldSync, oldElected, oldCfg := cacher.isLeader, syncInitDone, cacher.leaderElectedAt, systemConfigCache
	oldMod, oldGrace := dtrackModules, dtrackGrace
	oldOut, oldLevel := log.StandardLogger().Out, log.GetLevel()
	buf := &lockedBuf{}
	log.SetOutput(buf)
	log.SetLevel(log.DebugLevel)

	wlCacheMap, scanMap, dtrackPods = map[string]*workloadCache{}, map[string]*scanInfo{}, map[string]dtrackPod{}
	cacher.isLeader, syncInitDone, cacher.leaderElectedAt = true, true, time.Now().Add(-time.Hour)
	systemConfigCache.ClusterName = "c1"
	dtrackModules = func(id string) ([]*share.ScanModule, string, error) {
		return []*share.ScanModule{{Name: "libx", Version: "1.0", Source: "apk"}}, "alpine:3.18", nil
	}
	dtrackGrace = func(share.CLUSDependencyTrack) time.Duration { return 100 * time.Millisecond }
	t.Cleanup(func() {
		dtrackConfigUpdate(&share.CLUSSystemConfig{})
		dtrackMutex.Lock()
		dtrackLastKey = nil
		dtrackMutex.Unlock()
		wlCacheMap, scanMap, dtrackPods = oldWl, oldScan, oldPods
		cacher.isLeader, syncInitDone, cacher.leaderElectedAt, systemConfigCache = oldLeader, oldSync, oldElected, oldCfg
		dtrackModules, dtrackGrace = oldMod, oldGrace
		log.SetOutput(oldOut)
		log.SetLevel(oldLevel)
		if strings.Contains(buf.String(), dtrackTestKey) {
			t.Error("API key found in log output")
		}
	})
	return buf
}

func dtrackStart(f *fakeDTrack, mod func(*share.CLUSDependencyTrack)) {
	dt := share.CLUSDependencyTrack{Enabled: true, URL: f.URL, APIKey: dtrackTestKey}
	if mod != nil {
		mod(&dt)
	}
	dtrackConfigUpdate(&share.CLUSSystemConfig{DependencyTrack: dt})
}

// dtrackAddPod adds a scanned running container of pod pod. owner "" means a pod without owner.
func dtrackAddPod(id, ns, pod, owner string, labels map[string]string) {
	wlCacheMap[id] = &workloadCache{podName: pod, workload: &share.CLUSWorkload{
		ID: id, Domain: ns, Running: true, Image: "img:1", ImageDigest: "sha256:aaa",
		Labels: map[string]string{container.KubeKeyContainerName: "app"},
	}}
	scanMap[id] = &scanInfo{objType: share.ScanObjectType_CONTAINER, lastResult: share.ScanErrorCode_ScanErrNone, lastScanTime: time.Now()}
	dtrackPodUpdate(&resource.Pod{Name: pod, Domain: ns, OwnerName: owner, Labels: labels}, nil)
}

func TestDtrackPodsWithoutOwnerGetOwnProjects(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, nil)
	dtrackAddPod("w1", "ns", "pod-a", "", nil)
	dtrackAddPod("w2", "ns", "pod-b", "", nil)
	dtrackSweep(time.Now())
	f.waitUploads(t, 2)
	if f.uploads[0].name == f.uploads[1].name {
		t.Errorf("same project %q for two pods", f.uploads[0].name)
	}
	if want := "c1/ns/pod-a/app"; f.uploads[0].name != want && f.uploads[1].name != want {
		t.Errorf("project %q not found in %v", want, f.uploads)
	}
}

func TestDtrackReplicasShareProject(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, nil)
	for _, p := range []string{"web-1", "web-2", "web-3"} {
		dtrackAddPod("id-"+p, "ns", p, "web-rs", nil)
	}
	dtrackSweep(time.Now())
	f.waitUploads(t, 1)
	time.Sleep(200 * time.Millisecond)
	if u, _ := f.counts(); u != 1 {
		t.Errorf("want 1 upload, got %d", u)
	}
	if f.uploads[0].name != "c1/ns/web-rs/app" || f.uploads[0].version != "sha256:aaa" {
		t.Errorf("unexpected project %+v", f.uploads[0])
	}
}

func TestDtrackLabelSymbols(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, func(dt *share.CLUSDependencyTrack) {
		dt.Tags = []string{"{pod.metadata.labels.PRODUKT}", "{pod.metadata.labels.MISSING}", "{namespace.metadata.labels.team}"}
	})
	dtrackAddPod("w1", "ns", "pod-a", "rs", map[string]string{"PRODUKT": "x1"})
	domainCacheMap["ns"] = &domainCache{domain: &share.CLUSDomain{Name: "ns", Labels: map[string]string{"team": "blue"}}}
	t.Cleanup(func() { delete(domainCacheMap, "ns") })
	dtrackScanDone("w1")
	f.waitUploads(t, 1)
	if got := f.uploads[0].tags; got != "PRODUKT=x1,team=blue" && got != "x1,blue" {
		t.Errorf("tags %q", got)
	}
}

func TestDtrackMissingLabelInName(t *testing.T) {
	buf := dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, func(dt *share.CLUSDependencyTrack) { dt.ProjectName = "{pod.metadata.labels.PRODUKT}/{container}" })
	dtrackAddPod("w1", "ns", "pod-a", "rs", nil)
	dtrackScanDone("w1")
	time.Sleep(200 * time.Millisecond)
	if u, _ := f.counts(); u != 0 {
		t.Errorf("want no upload, got %d", u)
	}
	if !strings.Contains(buf.String(), "no upload to Dependency-Track") {
		t.Error("warning missing")
	}
}

func TestDtrackNotLeaderOrDisabled(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, nil)
	dtrackAddPod("w1", "ns", "pod-a", "rs", nil)
	cacher.isLeader = false
	dtrackScanDone("w1")
	dtrackSweep(time.Now())
	time.Sleep(200 * time.Millisecond)
	if u, _ := f.counts(); u != 0 {
		t.Errorf("not leader: want no upload, got %d", u)
	}

	cacher.isLeader = true
	dtrackStart(f, func(dt *share.CLUSDependencyTrack) { dt.Enabled = false })
	dtrackScanDone("w1")
	dtrackSweep(time.Now())
	time.Sleep(200 * time.Millisecond)
	if u, _ := f.counts(); u != 0 {
		t.Errorf("disabled: want no upload, got %d", u)
	}
}

// dtrackUploaded uploads one project, then removes its workload and waits longer than the grace period.
func dtrackUploaded(t *testing.T, f *fakeDTrack) {
	dtrackStart(f, nil)
	dtrackAddPod("w1", "ns", "pod-a", "rs", nil)
	dtrackSweep(time.Now())
	f.waitUploads(t, 1)
	time.Sleep(50 * time.Millisecond) // the worker records the entry after the upload
	delete(wlCacheMap, "w1")
	time.Sleep(200 * time.Millisecond)
}

func TestDtrackDeactivateAfterGrace(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackUploaded(t, f)
	dtrackMutex.Lock()
	dtrackStartedAt = time.Now().Add(-time.Hour)
	dtrackMutex.Unlock()
	dtrackSweep(time.Now())
	if _, p := f.counts(); p != 1 || f.patches[0] != `{"active":false}` {
		t.Errorf("patches %v", f.patches)
	}
}

func TestDtrackNoDeactivateWithoutGuards(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackUploaded(t, f)
	dtrackMutex.Lock()
	dtrackStartedAt = time.Now() // a restart
	dtrackMutex.Unlock()
	dtrackSweep(time.Now())
	if _, p := f.counts(); p != 0 {
		t.Errorf("uploader just started: got %d patches", p)
	}

	dtrackMutex.Lock()
	dtrackStartedAt = time.Now().Add(-time.Hour)
	dtrackMutex.Unlock()
	syncInitDone = false
	dtrackSweep(time.Now())
	if _, p := f.counts(); p != 0 {
		t.Errorf("no cache sync: got %d patches", p)
	}

	syncInitDone = true
	cacher.leaderElectedAt = time.Now()
	dtrackSweep(time.Now())
	if _, p := f.counts(); p != 0 {
		t.Errorf("leader just elected: got %d patches", p)
	}
}

func TestDtrackFreshUploaderDeactivatesNothing(t *testing.T) {
	dtrackEnv(t)
	f := newFakeDTrack(t)
	dtrackStart(f, nil)
	dtrackMutex.Lock()
	dtrackStartedAt = time.Now().Add(-time.Hour)
	dtrackMutex.Unlock()
	time.Sleep(200 * time.Millisecond)
	dtrackSweep(time.Now())
	if u, p := f.counts(); u != 0 || p != 0 {
		t.Errorf("uploads %d patches %d", u, p)
	}
}
