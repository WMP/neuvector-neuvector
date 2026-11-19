package cache

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/controller/sbom/s3store/s3fake"
	"github.com/neuvector/neuvector/share"
)

var (
	dPresent = "sha256:" + strings.Repeat("1", 64)
	dMissing = "sha256:" + strings.Repeat("2", 64)
	t0       = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
)

func keyOf(d string) string { return "c1/images/" + d + ".cdx.json.gz" }

// s3Env sets up a fake bucket with a present and a missing digest and a leader that is old enough.
func s3Env(t *testing.T, deleteUnused bool) *s3fake.Server {
	preTest()
	srv := s3fake.New()
	s3store.Configure(&share.CLUSSystemConfig{ClusterName: "c1", SBOMStorage: share.CLUSSBOMStorage{
		Enabled: true, Endpoint: srv.URL, PathStyle: true, Bucket: "bkt", AccessKey: "ak", SecretKey: "sk",
		DeleteUnused: deleteUnused, DeleteGrace: 1,
	}})
	srv.Put(keyOf(dPresent), []byte("x"))
	srv.Put(keyOf(dMissing), []byte("x"))

	oldInit, oldLeader, oldAt, oldWl := syncInitDone, cacher.isLeader, cacher.leaderElectedAt, wlCacheMap
	syncInitDone, cacher.isLeader, cacher.leaderElectedAt = true, true, t0.Add(-100*time.Hour)
	wlCacheMap = map[string]*workloadCache{
		"w1": {workload: &share.CLUSWorkload{ImageRepoDigests: []string{"repo/img@" + dPresent}}},
	}
	s3SweepReset()
	t.Cleanup(func() {
		syncInitDone, cacher.isLeader, cacher.leaderElectedAt, wlCacheMap = oldInit, oldLeader, oldAt, oldWl
		s3SweepReset()
		s3store.Configure(&share.CLUSSystemConfig{ClusterName: "c1"})
		srv.Close()
	})
	return srv
}

func hasObj(srv *s3fake.Server, d string) bool { _, ok := srv.Objects()[keyOf(d)]; return ok }

func TestS3SweepDeleteUnusedFalse(t *testing.T) {
	srv := s3Env(t, false)
	for i := 0; i < 5; i++ {
		s3Sweep(t0.Add(time.Duration(i) * 24 * time.Hour))
	}
	require.True(t, hasObj(srv, dMissing))
}

func TestS3SweepGrace(t *testing.T) {
	srv := s3Env(t, true)
	s3Sweep(t0) // first sight only
	require.True(t, hasObj(srv, dMissing))
	s3Sweep(t0.Add(30 * time.Second)) // before grace
	require.True(t, hasObj(srv, dMissing))
	s3Sweep(t0.Add(2 * time.Minute))
	require.False(t, hasObj(srv, dMissing))
	require.True(t, hasObj(srv, dPresent))
}

func TestS3SweepDigestReappears(t *testing.T) {
	srv := s3Env(t, true)
	s3Sweep(t0)
	wlCacheMap["w2"] = &workloadCache{workload: &share.CLUSWorkload{ImageDigest: dMissing}}
	s3Sweep(t0.Add(30 * time.Second)) // present again: timer dropped
	delete(wlCacheMap, "w2")
	s3Sweep(t0.Add(2 * time.Minute)) // first sight again
	require.True(t, hasObj(srv, dMissing))
	s3Sweep(t0.Add(4 * time.Minute))
	require.False(t, hasObj(srv, dMissing))
}

func TestS3SweepNotLeader(t *testing.T) {
	srv := s3Env(t, true)
	s3Sweep(t0)
	cacher.isLeader = false
	s3Sweep(t0.Add(time.Hour))
	require.True(t, hasObj(srv, dMissing))
	cacher.isLeader = true
	s3Sweep(t0.Add(2 * time.Hour)) // state was reset: first sight again
	require.True(t, hasObj(srv, dMissing))
}

func TestS3SweepSyncNotDone(t *testing.T) {
	srv := s3Env(t, true)
	s3Sweep(t0)
	syncInitDone = false
	s3Sweep(t0.Add(time.Hour))
	require.True(t, hasObj(srv, dMissing))
	syncInitDone = true
	s3Sweep(t0.Add(time.Hour)) // state kept: grace already passed
	require.False(t, hasObj(srv, dMissing))
}

func TestS3SweepRestart(t *testing.T) {
	srv := s3Env(t, true)
	s3SweepReset() // new process: no memory
	cacher.leaderElectedAt = t0
	s3Sweep(t0.Add(time.Minute - time.Second)) // first sight
	s3Sweep(t0.Add(time.Minute))               // missing > grace? no: 1s
	require.True(t, hasObj(srv, dMissing))
	// leaderElectedAt guard: even with old missingSince nothing goes before leader grace
	s3Sweeper.missingSince[dMissing] = t0.Add(-72 * time.Hour)
	s3Sweep(t0.Add(time.Minute - time.Second))
	require.True(t, hasObj(srv, dMissing))
}

func TestS3SweepLeaderLostAndRegained(t *testing.T) {
	srv := s3Env(t, true)
	s3Sweep(t0)
	LeadChangeNotify(false, "")
	cacher.isLeader = true
	s3Sweep(t0.Add(2 * time.Minute)) // first sight again
	require.True(t, hasObj(srv, dMissing))
	s3Sweep(t0.Add(4 * time.Minute))
	require.False(t, hasObj(srv, dMissing))
}

func TestS3SweepEmptyPresentSet(t *testing.T) {
	srv := s3Env(t, true)
	wlCacheMap = map[string]*workloadCache{}
	s3Sweep(t0)
	s3Sweep(t0.Add(time.Hour))
	require.Len(t, srv.Objects(), 2)
}

func TestS3SweepForeignObjects(t *testing.T) {
	srv := s3Env(t, true)
	srv.Put("other/images/"+dMissing+".cdx.json.gz", []byte("x"))
	srv.Put("c1/images/notadigest.cdx.json.gz", []byte("x"))
	srv.Put("c1/images/"+dMissing+".txt", []byte("x"))
	s3Sweep(t0)
	s3Sweep(t0.Add(time.Hour))
	require.False(t, hasObj(srv, dMissing))
	require.Len(t, srv.Objects(), 5-1)
}
