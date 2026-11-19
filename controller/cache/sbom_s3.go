package cache

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/controller/scan"
)

const s3SweepInterval = 10 * time.Minute

// Leader-only memory. It is lost on restart or leader change on purpose: a digest must be
// seen missing for a full grace period by the current leader before its object is deleted.
var s3Sweeper struct {
	sync.Mutex
	store        *s3store.Store
	gen          uint64
	missingSince map[string]time.Time
}

// s3SweepGen changes on every reset. A counter, not the lock: a running sweep holds the lock
// during S3 calls and a lead change must not wait for it.
var s3SweepGen atomic.Uint64

func s3SweepReset() { s3SweepGen.Add(1) }

func s3SweepLoop() {
	t := time.NewTicker(s3SweepInterval)
	defer t.Stop()
	for range t.C {
		s3Sweep(time.Now())
	}
}

// s3PresentDigests returns the digests of all registry images and all known workloads.
func s3PresentDigests() map[string]bool {
	present := scan.RegistryImageDigests()
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	for _, wlc := range wlCacheMap {
		if wlc.workload == nil {
			continue
		}
		if d := wlc.workload.ImageDigest; d != "" {
			present[d] = true
		}
		for _, rd := range wlc.workload.ImageRepoDigests {
			if _, d, ok := strings.Cut(rd, "@"); ok && d != "" {
				present[d] = true
			}
		}
	}
	return present
}

func s3Sweep(now time.Time) {
	st := s3store.Current()
	if st == nil || !st.DeleteUnused || !isLeader() {
		s3SweepReset()
		return
	}
	if !syncInitDone {
		return
	}

	s3Sweeper.Lock()
	defer s3Sweeper.Unlock()
	if gen := s3SweepGen.Load(); s3Sweeper.store != st || s3Sweeper.gen != gen || s3Sweeper.missingSince == nil {
		s3Sweeper.store, s3Sweeper.gen, s3Sweeper.missingSince = st, gen, make(map[string]time.Time)
	}

	present := s3PresentDigests()
	if len(present) == 0 {
		log.Debug("sbom s3: no image digest known, sweep skipped")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	objs, err := st.List(ctx)
	cancel()
	if err != nil {
		log.WithError(err).Warn("sbom s3: list failed, sweep skipped")
		return
	}

	listed := make(map[string]bool, len(objs))
	for _, o := range objs {
		d := o.Digest
		listed[d] = true
		since, seen := s3Sweeper.missingSince[d]
		switch {
		case present[d]:
			delete(s3Sweeper.missingSince, d)
		case !seen:
			s3Sweeper.missingSince[d] = now
		case now.Sub(since) > st.Grace && now.Sub(cacher.leaderElectedAt) > st.Grace && isLeader():
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := st.Delete(ctx, d)
			cancel()
			if err != nil {
				log.WithFields(log.Fields{"digest": d, "error": err}).Warn("sbom s3: delete failed")
			} else {
				log.WithFields(log.Fields{"digest": d}).Info("sbom s3: unused full SBOM deleted")
				delete(s3Sweeper.missingSince, d)
			}
		}
	}
	for d := range s3Sweeper.missingSince {
		if !listed[d] {
			delete(s3Sweeper.missingSince, d)
		}
	}
}
