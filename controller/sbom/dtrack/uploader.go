package dtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
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
	BOM     func() ([]byte, error) // builds the CycloneDX JSON when the item is sent; nil = only mark the project as seen
}

type entry struct {
	digest   string
	lastSeen time.Time
	inactive bool
	project  Project
	// parentUUID is the direct parent of the leaf at the last upload; a change runs the leaf check again
	parentUUID string
}

// parentEntry is a parent project that this uploader created or checked in DT.
type parentEntry struct {
	uuid       string
	parentUUID string
	depth      int // index in Project.Parents; deeper parents are deactivated first
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
	uploaded map[string]*entry       // only after a successful upload
	parents  map[string]*parentEntry // by parent project name; a hit needs no DT call
	pending  map[string][]string     // queued or waiting for a retry: key -> parents (they stay active)
	gen      uint64                  // Reset increments it; older items are ignored

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
		parents:     map[string]*parentEntry{},
		pending:     map[string][]string{},
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
	if it.BOM == nil {
		return false
	}
	key := it.Project.Key()
	u.mu.Lock()
	defer u.mu.Unlock()
	// An inactive project is sent again, so that it becomes active.
	// shortcut: dedup by image digest only, so packages that change at runtime are sent again only
	// with a new digest or after a restart; upgrade to a hash of the module list if that matters.
	if e := u.uploaded[key]; e != nil && e.digest == it.Digest && !e.inactive {
		return false
	}
	if _, ok := u.pending[key]; ok {
		return false
	}
	select {
	case u.queue <- queued{item: it, attempt: 1, gen: u.gen}:
		u.pending[key] = it.Project.Parents
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
	u.parents = map[string]*parentEntry{}
	u.pending = map[string][]string{}
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

	// The parents come first (root first), so that the leaf is created or moved below an active parent.
	pctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	parentUUID, err := u.ensureParents(pctx, q.gen, q.item.Project)
	cancel()
	if errors.Is(err, errNotFound) && q.attempt == 1 {
		// a cached parent may be deleted in DT: check the parents again on the retry (once)
		u.forgetParents(q.gen, q.item.Project)
		err = fmt.Errorf("parent project not found, checked again: %v", err)
	} else if errors.Is(err, errRejected) {
		// e.g. a key without PORTFOLIO_MANAGEMENT: send the SBOM without parent rather than not at all
		log.WithFields(fields).WithError(err).Warn("dtrack: parent project refused, upload without parent")
		parentUUID, err = "", nil
	}

	// A project this uploader does not know (first upload, after a restart or Reset), one it deactivated
	// or one with another parent than before (an existing flat project of an older version) may be inactive
	// or have no parent in DT. DT accepts the upload to an inactive project, but it would stay hidden, and it
	// sets the parent only for a project that it creates. A missing project is not an error.
	stillInactive := false
	leafParent := parentUUID // the parent of the leaf in DT after this upload; "" = check it again next time
	if err == nil {
		u.mu.Lock()
		old := u.uploaded[key]
		u.mu.Unlock()
		if old == nil || old.inactive || old.parentUUID != parentUUID {
			sctx, cancel := context.WithTimeout(ctx, uploadTimeout)
			if serr := u.fixLeaf(sctx, q.item.Project, parentUUID); serr != nil {
				log.WithFields(fields).WithError(serr).Warn("dtrack: cannot activate or move project")
				stillInactive = old != nil && old.inactive // the next Enqueue sends it again; an unknown project is not retried
				leafParent = ""                            // a new digest tries the move again
			}
			cancel()
		}

		uctx, cancel := context.WithTimeout(ctx, uploadTimeout)
		err = u.c.Upload(uctx, q.item.Project, parentUUID, bom)
		cancel()
		if errors.Is(err, errNotFound) && parentUUID != "" && q.attempt == 1 {
			// the cached parent may be deleted in DT: check the parents again on the retry (once)
			u.forgetParents(q.gen, q.item.Project)
			err = fmt.Errorf("parent project not found, checked again: %v", err)
		}
	}

	switch {
	case err == nil:
		log.WithFields(fields).WithField("size", len(bom)).Info("dtrack: SBOM uploaded")
	case errors.Is(err, ErrTooLarge):
		log.WithFields(fields).Error(err.Error())
	case ctx.Err() != nil: // uploader stopped
		u.done(q, key)
		return
	case errors.Is(err, errRejected):
		// recorded like 413: sent again only with a new digest or a new configuration (e.g. a new API key)
		log.WithFields(fields).WithError(err).Warn("dtrack: upload rejected, not sent again for this image")
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

	// Success, too large or rejected: remember the digest. The same digest is not sent again.
	u.mu.Lock()
	if q.gen == u.gen {
		u.uploaded[key] = &entry{digest: q.item.Digest, project: q.item.Project, lastSeen: u.now(), inactive: stillInactive, parentUUID: leafParent}
	}
	u.mu.Unlock()
	u.done(q, key)
}

// fixLeaf activates the leaf and moves it below parentUUID when it exists in DT.
func (u *Uploader) fixLeaf(ctx context.Context, p Project, parentUUID string) error {
	cur, err := u.c.lookup(ctx, p.Name, p.Version)
	if err != nil || cur == nil {
		return err // a missing leaf is created by the upload, with the parent
	}
	return u.syncProject(ctx, cur, parentUUID)
}

// syncProject sends one PATCH with the active flag and the parent, only for what differs.
func (u *Uploader) syncProject(ctx context.Context, cur *dtProject, parentUUID string) error {
	var active *bool
	if !cur.Active {
		active = new(bool)
		*active = true
	}
	if parentUUID == cur.ParentUUID {
		parentUUID = ""
	}
	if active == nil && parentUUID == "" {
		return nil
	}
	return u.c.patch(ctx, cur.UUID, active, parentUUID)
}

// ensureParents makes sure that all parents of p exist, are active and have the right parent, root first.
// It returns the UUID of the direct parent of the leaf ("" without parents). A cached parent needs no DT call.
func (u *Uploader) ensureParents(ctx context.Context, gen uint64, p Project) (string, error) {
	wanted := ""
	for i, name := range p.Parents {
		u.mu.Lock()
		c := u.parents[name]
		u.mu.Unlock()
		if c != nil && c.parentUUID == wanted {
			wanted = c.uuid
			continue
		}
		cur, err := u.c.lookup(ctx, name, "") // no version: parents have none
		if err == nil && cur == nil {
			cur, err = u.c.create(ctx, name, wanted)
		}
		var uuid string
		if err == nil {
			// also for a project created meanwhile by someone else: it may be inactive or elsewhere
			uuid, err = cur.UUID, u.syncProject(ctx, cur, wanted)
		}
		if err != nil {
			return "", fmt.Errorf("parent project %q: %w", name, err)
		}
		u.mu.Lock()
		if gen == u.gen {
			u.parents[name] = &parentEntry{uuid: uuid, parentUUID: wanted, depth: i}
		}
		u.mu.Unlock()
		wanted = uuid
	}
	return wanted, nil
}

// forgetParents drops the cached parents of p, so that ensureParents checks them in DT again.
func (u *Uploader) forgetParents(gen uint64, p Project) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if gen == u.gen {
		for _, n := range p.Parents {
			delete(u.parents, n)
		}
	}
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
		u.mu.Lock()
		stale := gen != u.gen // Reset: leadership lost or uploader stopped
		u.mu.Unlock()
		if stale || ctx.Err() != nil {
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
		// Forget the project: if it comes back (also if the worker stored it meanwhile), the next upload
		// checks the active flag in DT again. This also keeps the map small.
		u.mu.Lock()
		if gen == u.gen {
			delete(u.uploaded, g.key)
		}
		u.mu.Unlock()
		log.WithFields(fields).Info("dtrack: project deactivated")
	}
	u.deactivateParents(ctx, gen)
}

// deactivateParents deactivates the cached parents that no live leaf has, deepest first, so that DT
// accepts it (no active children). A parent that DT refuses (e.g. 409: it has active children that this
// uploader does not know) is warned once and forgotten, not retried: a leaf uploaded below it checks it again.
func (u *Uploader) deactivateParents(ctx context.Context, gen uint64) {
	type cand struct {
		name  string
		depth int
	}
	var list []cand
	u.mu.Lock()
	live := map[string]bool{}
	for _, e := range u.uploaded {
		for _, n := range e.project.Parents {
			live[n] = true
		}
	}
	for _, parents := range u.pending { // a leaf on its way must not lose its parents
		for _, n := range parents {
			live[n] = true
		}
	}
	for n, pe := range u.parents {
		if !live[n] {
			list = append(list, cand{n, pe.depth})
		}
	}
	u.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].depth > list[j].depth })
	for _, c := range list {
		u.mu.Lock()
		stale := gen != u.gen
		used := false
		for _, parents := range u.pending { // queued since the list was made
			used = used || slices.Contains(parents, c.name)
		}
		if !used {
			// forget it first: a leaf queued from now on checks the parent in DT (and activates it again)
			delete(u.parents, c.name)
		}
		u.mu.Unlock()
		if stale || ctx.Err() != nil {
			return
		}
		if used {
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, uploadTimeout)
		err := u.c.SetActive(sctx, c.name, "", false)
		cancel()
		fields := log.Fields{"project": c.name}
		if err != nil {
			log.WithFields(fields).WithError(err).Warn("dtrack: cannot deactivate parent project")
		} else {
			log.WithFields(fields).Info("dtrack: parent project deactivated")
		}
	}
}
