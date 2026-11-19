package dtrack

import (
	"context"
	"fmt"
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
	if f.patches[0] != `{"active":false}` || f.lookups != 1 {
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
