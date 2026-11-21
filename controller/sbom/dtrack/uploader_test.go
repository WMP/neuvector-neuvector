package dtrack

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func newTestUploader(t *testing.T, f *fakeDT) *Uploader {
	u := NewUploader(f.client())
	u.retryBase, u.retryMax = 5*time.Millisecond, 20*time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return u
}

func item(name, digest string) Item {
	return Item{ID: "w-" + name, Project: Project{Name: name, Version: "v1"}, Digest: digest,
		BOM: func() ([]byte, error) { return []byte("{\n  \"a\": 1\n}"), nil }}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func (u *Uploader) idle() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.pending) == 0
}

func TestDedup(t *testing.T) {
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	for i := 0; i < 5; i++ { // 5 replicas, same project
		u.Enqueue(item("p1", "d1"))
	}
	waitFor(t, "first upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	if u.Enqueue(item("p1", "d1")) {
		t.Error("same digest queued again")
	}
	if f.uploads[0].BOM != `{"a":1}` {
		t.Errorf("bom not compacted: %q", f.uploads[0].BOM)
	}
	u.Enqueue(item("p1", "d2"))
	u.Enqueue(item("p2", "d1"))
	waitFor(t, "3 uploads", func() bool { n, _ := f.counts(); return n == 3 && u.idle() })
	time.Sleep(20 * time.Millisecond)
	if n, _ := f.counts(); n != 3 {
		t.Errorf("uploads = %d, want 3", n)
	}
}

func TestRetry(t *testing.T) {
	f := newFakeDT(t)
	f.bomStatuses = []int{503, 503}
	u := newTestUploader(t, f)
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "retry success", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	if f.bomCalls != 3 {
		t.Errorf("calls = %d, want 3", f.bomCalls)
	}
}

func TestRetryMaxAttempts(t *testing.T) {
	f := newFakeDT(t)
	f.bomStatuses = make([]int, 100)
	for i := range f.bomStatuses {
		f.bomStatuses[i] = 503
	}
	u := newTestUploader(t, f)
	u.maxAttempts = 3
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "give up", u.idle)
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bomCalls != 3 || len(f.uploads) != 0 {
		t.Errorf("calls %d uploads %d", f.bomCalls, len(f.uploads))
	}
}

func TestTooLargeNoRetry(t *testing.T) {
	buf := captureLogs(t)
	f := newFakeDT(t)
	f.bomStatuses = []int{413, 413}
	u := newTestUploader(t, f)
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "413", func() bool { return u.idle() })
	time.Sleep(30 * time.Millisecond)
	if f.bomCalls != 1 {
		t.Errorf("calls = %d, want 1", f.bomCalls)
	}
	if !strings.Contains(buf.String(), "proxy-body-size") {
		t.Errorf("log: %s", buf.String())
	}
	if u.Enqueue(item("p1", "d1")) {
		t.Error("same digest sent again after 413")
	}
	if !u.Enqueue(item("p1", "d2")) { // new digest tries again
		t.Error("new digest not queued")
	}
	waitFor(t, "second try", func() bool { return u.idle() && f.bomCalls == 2 })
}

func TestInactiveAndActive(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	clock := time.Unix(1000, 0)
	u.now = func() time.Time { return clock }
	grace := time.Hour
	ctx := t.Context()

	u.Enqueue(item("p1", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })

	clock = clock.Add(grace / 2)
	u.Sweep(ctx, nil, grace, true)
	clock = clock.Add(grace) // past grace
	u.Sweep(ctx, nil, grace, false)
	if _, p := f.counts(); p != 0 {
		t.Fatalf("PATCH before allowed: %v", f.patches)
	}
	u.Sweep(ctx, nil, grace, true)
	if f.patches[0] != `{"active":false}` || f.lookups != 2 { // first upload checks the active flag too
		t.Fatalf("patches %v lookups %d", f.patches, f.lookups)
	}
	u.Sweep(ctx, nil, grace, true) // already inactive: no second call
	if _, p := f.counts(); p != 1 {
		t.Errorf("patches = %d", p)
	}

	u.Sweep(ctx, []Item{item("p1", "d2")}, grace, true)
	waitFor(t, "reactivate", func() bool { n, p := f.counts(); return n == 2 && p == 2 && u.idle() })
	if f.patches[1] != `{"active":true}` {
		t.Errorf("patches %v", f.patches)
	}
}

func TestRestartNoDeactivate(t *testing.T) {
	f := newFakeDT(t)
	u := NewUploader(f.client()) // empty state
	u.now = func() time.Time { return time.Unix(1<<30, 0) }
	u.Sweep(t.Context(), nil, time.Minute, true)
	if f.lookups != 0 {
		t.Errorf("lookups = %d", f.lookups)
	}
	if _, p := f.counts(); p != 0 {
		t.Errorf("patches = %d", p)
	}
}

func TestResetDropsRetry(t *testing.T) {
	f := newFakeDT(t)
	f.bomStatuses = []int{503}
	u := newTestUploader(t, f)
	u.retryBase, u.retryMax = 100*time.Millisecond, 100*time.Millisecond
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "first failure", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.bomCalls == 1 })
	u.Reset()
	time.Sleep(250 * time.Millisecond)
	if n, _ := f.counts(); n != 0 {
		t.Errorf("upload after Reset: %d", n)
	}
	f.mu.Lock()
	calls := f.bomCalls
	f.mu.Unlock()
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestBOMErrorDropsItem(t *testing.T) {
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	it := item("p1", "d1")
	it.BOM = func() ([]byte, error) { return nil, fmt.Errorf("boom") }
	u.Enqueue(it)
	waitFor(t, "drop", u.idle)
	if n, _ := f.counts(); n != 0 {
		t.Errorf("uploads = %d", n)
	}
}

func TestUnknownProjectActivatedAndNoRetryOn401(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	f.add("p1", "v1", false, "") // inactive in DT, unknown to this (restarted) uploader
	u := newTestUploader(t, f)
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "upload", func() bool { n, p := f.counts(); return n == 1 && p == 1 && u.idle() })
	if f.patches[0] != `{"active":true}` {
		t.Errorf("patches %v", f.patches)
	}

	f.mu.Lock()
	f.bomStatuses = []int{http.StatusUnauthorized, http.StatusUnauthorized}
	f.mu.Unlock()
	u.Enqueue(item("p2", "d1"))
	waitFor(t, "rejected", func() bool { return u.idle() })
	time.Sleep(50 * time.Millisecond)
	f.mu.Lock()
	calls := f.bomCalls
	f.mu.Unlock()
	if calls != 2 {
		t.Errorf("401 must not be retried: %d upload calls", calls)
	}
}

// deep returns an item with parents c, c/ns; the leaf is c/ns/<leaf>.
func deep(parents []string, leaf, digest string) Item {
	it := item(leaf, digest)
	it.Project.Parents = parents
	return it
}

var chain = []string{"c", "c/ns"}

func (f *fakeDT) parentOf(name, version string) string {
	p := f.get(name, version)
	if p == nil {
		return "<missing>"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if pp := f.byUUID(p.parent); pp != nil {
		return pp.name
	}
	return ""
}

func TestParentChainCreated(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	want := "lookup c; PUT c; lookup c/ns; PUT c/ns; lookup c/ns/a; upload c/ns/a"
	if got := f.callsString(); got != want {
		t.Errorf("calls:\n got %s\nwant %s", got, want)
	}
	for name, parent := range map[string]string{"c": "", "c/ns": "c", "c/ns/a": "c/ns"} {
		v := ""
		if name == "c/ns/a" {
			v = "v1"
		}
		if got := f.parentOf(name, v); got != parent {
			t.Errorf("parent of %s = %q, want %q", name, got, parent)
		}
	}
	if f.uploads[0].Fields["parentUUID"] != f.get("c/ns", "").uuid {
		t.Errorf("parentUUID field %q", f.uploads[0].Fields["parentUUID"])
	}
	if len(f.patches) != 0 {
		t.Errorf("patches %v", f.patches)
	}
}

func TestFlatItemNoParentCalls(t *testing.T) {
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	u.Enqueue(item("p1", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	if _, ok := f.uploads[0].Fields["parentUUID"]; ok || len(f.puts) != 0 {
		t.Errorf("fields %v puts %v", f.uploads[0].Fields, f.puts)
	}
}

func TestExistingFlatLeafGetsParent(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	f.add("c/ns/a", "v1", false, "") // from the previous version: flat and inactive
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	if got := f.parentOf("c/ns/a", "v1"); got != "c/ns" {
		t.Errorf("parent = %q", got)
	}
	if !f.get("c/ns/a", "v1").active {
		t.Error("leaf not active")
	}
	if len(f.patches) != 1 || !strings.Contains(f.patches[0], `"active":true`) || !strings.Contains(f.patches[0], `"parent"`) {
		t.Errorf("want one PATCH with active and parent: %v", f.patches)
	}
}

func TestParentCache(t *testing.T) {
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "first", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	u.Enqueue(deep(chain, "c/ns/b", "d1"))
	waitFor(t, "second", func() bool { n, _ := f.counts(); return n == 2 && u.idle() })
	if got := f.callsString(); got != "lookup c/ns/b; upload c/ns/b" {
		t.Errorf("calls: %s", got)
	}
}

func TestParentErrorRetried(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	f.lookupCode = 500
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "lookups retried", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lookups >= 2 })
	f.mu.Lock()
	f.lookupCode = 0
	f.mu.Unlock()
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
}

func TestCascadeInactive(t *testing.T) {
	buf := captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	clock := time.Unix(1000, 0)
	u.now = func() time.Time { return clock }
	grace := time.Hour
	ctx := t.Context()
	other := []string{"c", "c/other"}

	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	u.Enqueue(deep(other, "c/other/b", "d1"))
	waitFor(t, "uploads", func() bool { n, _ := f.counts(); return n == 2 && u.idle() })

	// a is gone, b is seen: a and c/ns are deactivated, c (parent of b) and c/other stay active
	clock = clock.Add(2 * grace)
	u.Sweep(ctx, []Item{deep(other, "c/other/b", "d1")}, grace, true)
	for name, v := range map[string]string{"c/ns/a": "v1", "c/ns": ""} {
		if f.get(name, v).active {
			t.Errorf("%s still active", name)
		}
	}
	for name, v := range map[string]string{"c": "", "c/other": "", "c/other/b": "v1"} {
		if !f.get(name, v).active {
			t.Errorf("%s inactive", name)
		}
	}

	// b is gone: leaf, then the deepest parent, then the root
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	clock = clock.Add(2 * grace)
	u.Sweep(ctx, nil, grace, true)
	want := "lookup c/other/b; PATCH c/other/b; lookup c/other; PATCH c/other; lookup c; PATCH c"
	if got := f.callsString(); got != want {
		t.Errorf("calls:\n got %s\nwant %s", got, want)
	}
	if f.get("c", "").active {
		t.Error("root still active")
	}
	if !strings.Contains(buf.String(), "parent project deactivated") {
		t.Errorf("log: %s", buf.String())
	}

	// all forgotten: nothing more happens
	_, p := f.counts()
	u.Sweep(ctx, nil, grace, true)
	if _, p2 := f.counts(); p2 != p {
		t.Errorf("patches %d -> %d", p, p2)
	}
}

func TestCascadeRefusedOnce(t *testing.T) {
	buf := captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	clock := time.Unix(1000, 0)
	u.now = func() time.Time { return clock }
	grace := time.Hour
	ctx := t.Context()

	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	f.add("unknown", "v", true, f.get("c/ns", "").uuid) // active child that the uploader does not know

	clock = clock.Add(2 * grace)
	u.Sweep(ctx, nil, grace, true)
	u.Sweep(ctx, nil, grace, true)
	if !f.get("c/ns", "").active || !f.get("c", "").active {
		t.Error("parents with an active child must stay active")
	}
	if n := strings.Count(buf.String(), "cannot deactivate parent project"); n != 2 { // c/ns and c, once each
		t.Errorf("warnings = %d: %s", n, buf.String())
	}
	if n := strings.Count(f.callsString()+";", "PATCH c/ns;"); n != 1 {
		t.Errorf("calls: %s", f.callsString())
	}
}

func TestLeafComesBackReactivatesParents(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	clock := time.Unix(1000, 0)
	u.now = func() time.Time { return clock }
	grace := time.Hour
	ctx := t.Context()

	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	clock = clock.Add(2 * grace)
	u.Sweep(ctx, nil, grace, true)
	if f.get("c", "").active {
		t.Fatal("root not deactivated")
	}

	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
	u.Sweep(ctx, []Item{deep(chain, "c/ns/a", "d1")}, grace, true)
	waitFor(t, "second upload", func() bool { n, _ := f.counts(); return n == 2 && u.idle() })
	want := "lookup c; PATCH c; lookup c/ns; PATCH c/ns; lookup c/ns/a; PATCH c/ns/a; upload c/ns/a"
	if got := f.callsString(); got != want {
		t.Errorf("calls:\n got %s\nwant %s", got, want)
	}
}

func TestRestartWithParentsNoPatch(t *testing.T) {
	f := newFakeDT(t)
	f.add("c", "", true, "")
	u := NewUploader(f.client())
	u.now = func() time.Time { return time.Unix(1<<30, 0) }
	u.Sweep(t.Context(), nil, time.Minute, true)
	if len(f.calls) != 0 {
		t.Errorf("calls: %v", f.calls)
	}
}

func TestParentRefusedUploadsWithoutParent(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	f.putCode = http.StatusForbidden // key without PORTFOLIO_MANAGEMENT
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	if got := f.uploads[0].Fields["parentUUID"]; got != "" {
		t.Errorf("parentUUID %q, want none", got)
	}
}

func TestDeletedParentCreatedAgain(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "first upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	f.mu.Lock()
	delete(f.projects, "c/ns\x00") // deleted in the DT UI; the uploader still caches its UUID
	f.mu.Unlock()
	u.Enqueue(deep(chain, "c/ns/b", "d1"))
	waitFor(t, "second upload", func() bool { n, _ := f.counts(); return n == 2 && u.idle() })
	if got := f.parentOf("c/ns/b", "v1"); got != "c/ns" {
		t.Errorf("parent of c/ns/b = %q", got)
	}
}

func TestDeletedCachedRootCreatedAgain(t *testing.T) {
	captureLogs(t)
	f := newFakeDT(t)
	u := newTestUploader(t, f)
	u.Enqueue(deep(chain, "c/ns/a", "d1"))
	waitFor(t, "first upload", func() bool { n, _ := f.counts(); return n == 1 && u.idle() })
	f.mu.Lock()
	delete(f.projects, "c\x00") // the cached root is deleted in DT; a new namespace needs a new child of it
	f.mu.Unlock()
	u.Enqueue(deep([]string{"c", "c/ns2"}, "c/ns2/a", "d1"))
	waitFor(t, "second upload", func() bool { n, _ := f.counts(); return n == 2 && u.idle() })
	if got := f.parentOf("c/ns2", ""); got != "c" {
		t.Errorf("parent of c/ns2 = %q", got)
	}
}
