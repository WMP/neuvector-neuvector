package dtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	queueSize     = 1000
	uploadTimeout = 2 * time.Minute
)

// Item is one workload project to upload.
type Item struct {
	ID      string // workload ID, only for logs
	Project Project
	Digest  string                 // same Project.Key() and Digest as the last successful upload = skip
	BOM     func() ([]byte, error) // builds the CycloneDX JSON when the item is sent
}

type entry struct {
	digest   string
	lastSeen time.Time
	inactive bool
	project  Project
}

type queued struct {
	item    Item
	attempt int
	gen     uint64
}

// Uploader sends SBOMs to DT with one worker. It runs on the cluster leader only.
type Uploader struct {
	c     *Client
	queue chan queued

	mu       sync.Mutex
	uploaded map[string]*entry // only after a successful upload
	pending  map[string]bool   // queued or waiting for a retry
	gen      uint64            // Reset increments it; older items are ignored

	// unexported so tests can change them
	retryBase, retryMax time.Duration
	maxAttempts         int
	now                 func() time.Time
}

func NewUploader(c *Client) *Uploader {
	return &Uploader{
		c:           c,
		queue:       make(chan queued, queueSize),
		uploaded:    map[string]*entry{},
		pending:     map[string]bool{},
		retryBase:   30 * time.Second,
		retryMax:    30 * time.Minute,
		maxAttempts: 8,
		now:         time.Now,
	}
}

// Run is the worker loop. It returns when ctx is done.
func (u *Uploader) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-u.queue:
			u.process(ctx, q)
		}
	}
}

// Enqueue never blocks. It returns false when the item is not queued.
func (u *Uploader) Enqueue(it Item) bool {
	key := it.Project.Key()
	u.mu.Lock()
	defer u.mu.Unlock()
	// An inactive project is sent again, so that it becomes active.
	if e := u.uploaded[key]; e != nil && e.digest == it.Digest && !e.inactive {
		return false
	}
	if u.pending[key] {
		return false
	}
	select {
	case u.queue <- queued{item: it, attempt: 1, gen: u.gen}:
		u.pending[key] = true
		return true
	default:
		return false
	}
}

// Reset forgets all state. Queued items and retries of the old state are dropped.
func (u *Uploader) Reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.gen++
	u.uploaded = map[string]*entry{}
	u.pending = map[string]bool{}
}

func (u *Uploader) process(ctx context.Context, q queued) {
	key := q.item.Project.Key()
	fields := log.Fields{"project": q.item.Project.Name, "version": q.item.Project.Version, "workload": q.item.ID}
	u.mu.Lock()
	stale := q.gen != u.gen
	u.mu.Unlock()
	if stale {
		return
	}

	bom, err := q.item.BOM()
	if err != nil {
		log.WithFields(fields).WithError(err).Warn("dtrack: cannot build SBOM, item dropped")
		u.done(q, key)
		return
	}
	var buf bytes.Buffer
	if json.Compact(&buf, bom) == nil {
		bom = buf.Bytes()
	}

	uctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	err = u.c.Upload(uctx, q.item.Project, bom)
	cancel()

	switch {
	case err == nil:
		log.WithFields(fields).WithField("size", len(bom)).Info("dtrack: SBOM uploaded")
	case errors.Is(err, ErrTooLarge):
		log.WithFields(fields).Error(err.Error())
	default:
		fields["attempt"] = q.attempt
		if q.attempt >= u.maxAttempts {
			log.WithFields(fields).WithError(err).Warn("dtrack: upload failed, giving up until next sweep")
			u.done(q, key)
			return
		}
		log.WithFields(fields).WithError(err).Warn("dtrack: upload failed, will retry")
		delay := u.retryBase << (q.attempt - 1)
		if delay > u.retryMax || delay <= 0 {
			delay = u.retryMax
		}
		q.attempt++
		time.AfterFunc(delay, func() { u.requeue(q) })
		return
	}

	// Success or too large: remember the digest. Too large is not retried with the same digest.
	e := &entry{digest: q.item.Digest, project: q.item.Project}
	wasInactive := false
	u.mu.Lock()
	if q.gen == u.gen {
		if old := u.uploaded[key]; old != nil {
			e.inactive, wasInactive = old.inactive, old.inactive
		}
		e.lastSeen = u.now()
		u.uploaded[key] = e
	}
	u.mu.Unlock()
	if err == nil && wasInactive {
		sctx, cancel := context.WithTimeout(ctx, uploadTimeout)
		serr := u.c.SetActive(sctx, e.project.Name, e.project.Version, true)
		cancel()
		if serr != nil {
			// Stays inactive here, so the next Enqueue sends the item again.
			log.WithFields(fields).WithError(serr).Warn("dtrack: cannot activate project")
		} else {
			u.mu.Lock()
			e.inactive = false
			u.mu.Unlock()
		}
	}
	u.done(q, key)
}

// done clears the pending flag of the item (if its generation is current).
func (u *Uploader) done(q queued, key string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if q.gen == u.gen {
		delete(u.pending, key)
	}
}

// requeue runs from a retry timer.
func (u *Uploader) requeue(q queued) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if q.gen != u.gen {
		return
	}
	select {
	case u.queue <- q:
	default:
		delete(u.pending, q.item.Project.Key()) // queue full: a later Sweep queues it again
	}
}

// Sweep queues the items and marks projects that are gone for longer than grace as inactive in DT.
// The caller sets canDeactivate only as leader, after a full cache sync.
// After Reset or a restart no entry exists, so nothing is deactivated before a project was uploaded again.
func (u *Uploader) Sweep(ctx context.Context, items []Item, grace time.Duration, canDeactivate bool) {
	now := u.now()
	u.mu.Lock()
	for _, it := range items {
		if e := u.uploaded[it.Project.Key()]; e != nil {
			e.lastSeen = now
		}
	}
	u.mu.Unlock()
	for _, it := range items {
		u.Enqueue(it)
	}
	if !canDeactivate {
		return
	}

	type gone struct {
		key string
		p   Project
	}
	var list []gone
	u.mu.Lock()
	gen := u.gen
	for k, e := range u.uploaded {
		if !e.inactive && now.Sub(e.lastSeen) > grace {
			list = append(list, gone{k, e.project})
		}
	}
	u.mu.Unlock()
	for _, g := range list {
		if ctx.Err() != nil { // uploader stopped (DT disabled or reconfigured)
			return
		}
		sctx, cancel := context.WithTimeout(ctx, uploadTimeout)
		err := u.c.SetActive(sctx, g.p.Name, g.p.Version, false)
		cancel()
		fields := log.Fields{"project": g.p.Name, "version": g.p.Version}
		if err != nil {
			log.WithFields(fields).WithError(err).Warn("dtrack: cannot deactivate project")
			continue
		}
		u.mu.Lock()
		// the worker may have stored a new entry meanwhile: mark the current one, so that
		// a project that came back is uploaded and activated again by the next Enqueue
		if e := u.uploaded[g.key]; gen == u.gen && e != nil {
			e.inactive = true
		}
		u.mu.Unlock()
		log.WithFields(fields).Info("dtrack: project deactivated")
	}
}
