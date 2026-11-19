package cache

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/sbom"
	"github.com/neuvector/neuvector/controller/sbom/dtrack"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/httpclient"
)

const dtrackSweepInterval = 5 * time.Minute

// Test seams: dtrackModules reads the scan modules of a workload from the database,
// dtrackGrace converts the grace period (minutes) so that tests do not wait.
var dtrackGrace = dtrack.Grace
var dtrackModules = func(id string) ([]*share.ScanModule, string, error) { return cacher.GetScanModules(id) }

type dtrackPod struct {
	ownerName string
	labels    map[string]string
}

// dtrackConfigKey holds everything that changes the uploader. It is never logged.
type dtrackConfigKey struct {
	DT              share.CLUSDependencyTrack
	TLSVerification bool
	CaCerts         []string
	HttpProxy       share.CLUSProxy
	HttpsProxy      share.CLUSProxy
}

var (
	dtrackPodMutex sync.Mutex
	dtrackPods     = make(map[string]dtrackPod) // key: domain/name

	dtrackMutex     sync.Mutex
	dtrackUploader  *dtrack.Uploader
	dtrackCancel    context.CancelFunc
	dtrackCtx       context.Context           // done when the uploader is stopped
	dtrackCfg       share.CLUSDependencyTrack // defaults applied
	dtrackStartedAt time.Time
	dtrackLastKey   *dtrackConfigKey
)

// dtrackPodUpdate keeps the pod owner and labels. It runs on every controller.
func dtrackPodUpdate(n, o *resource.Pod) {
	dtrackPodMutex.Lock()
	defer dtrackPodMutex.Unlock()
	if n != nil {
		dtrackPods[n.Domain+"/"+n.Name] = dtrackPod{ownerName: n.OwnerName, labels: n.Labels}
	} else if o != nil {
		delete(dtrackPods, o.Domain+"/"+o.Name)
	}
}

// dtrackConfigUpdate (re)starts the uploader when the Dependency-Track settings change.
// shortcut: the uploaded keys live in the leader's memory, so projects uploaded before a restart, failover
// or config change are never set inactive (safe, never wrong); keep the keys in KV if that is needed.
func dtrackConfigUpdate(cfg *share.CLUSSystemConfig) {
	key := &dtrackConfigKey{cfg.DependencyTrack, cfg.EnableTLSVerification, cfg.GlobalCaCerts, cfg.RegistryHttpProxy, cfg.RegistryHttpsProxy}

	dtrackMutex.Lock()
	defer dtrackMutex.Unlock()
	if dtrackLastKey != nil && reflect.DeepEqual(dtrackLastKey, key) {
		return
	}
	dtrackLastKey = key
	if dtrackCancel != nil {
		dtrackCancel()
		dtrackCancel, dtrackUploader = nil, nil
	}
	dt := cfg.DependencyTrack
	if !dt.Enabled {
		return
	}
	if localDev != nil && localDev.Host.Platform != share.PlatformKubernetes {
		log.Warn("dtrack: the project templates need Kubernetes pods; nothing is uploaded on this platform")
	}

	proxy := httpclient.GetHttpProxy()
	if strings.HasPrefix(strings.ToLower(dt.URL), "https:") {
		proxy = httpclient.GetHttpsProxy()
	}
	hc, err := httpclient.CreateHTTPClient(proxy)
	if err != nil {
		log.WithFields(log.Fields{"url": dt.URL, "error": err}).Warn("dtrack: cannot create HTTP client, uploader not started")
		dtrackLastKey = nil // try again on the next system config update
		return
	}
	u := dtrack.NewUploader(&dtrack.Client{URL: strings.TrimRight(dt.URL, "/"), APIKey: dt.APIKey, HTTP: hc})
	ctx, cancel := context.WithCancel(context.Background())
	go u.Run(ctx)
	dtrackUploader, dtrackCancel, dtrackCtx = u, cancel, ctx
	dtrackCfg, dtrackStartedAt = dtrack.WithDefaults(dt), time.Now()
	log.WithFields(log.Fields{"enabled": true, "url": dt.URL}).Info("dtrack: uploader started")
}

func dtrackState() (*dtrack.Uploader, share.CLUSDependencyTrack, time.Time, context.Context) {
	dtrackMutex.Lock()
	defer dtrackMutex.Unlock()
	return dtrackUploader, dtrackCfg, dtrackStartedAt, dtrackCtx
}

// errDtrackPodUnknown: the pod event has not arrived yet (or the pod is deleted). Without it, a pod
// with an owner would look like a pod without owner and get a project of its own.
var errDtrackPodUnknown = errors.New("pod not known yet")

// dtrackItem builds the upload item of a workload. It returns nil, nil when the workload is gone or stopped.
// The SBOM is built when the item is sent, so this does not read the database.
func dtrackItem(id string, cfg share.CLUSDependencyTrack) (*dtrack.Item, error) {
	cacheMutexRLock()
	c := wlCacheMap[id]
	if c == nil || c.workload == nil || !c.workload.Running {
		cacheMutexRUnlock()
		return nil, nil
	}
	wl := *c.workload
	podName := c.podName
	cluster := systemConfigCache.ClusterName
	cacheMutexRUnlock()

	digest := wl.ImageDigest
	if digest == "" {
		digest = wl.ImageID
	}
	v := dtrack.Vars{
		Cluster:   cluster,
		Namespace: wl.Domain,
		Service:   wl.Service,
		Pod:       podName,
		Container: wl.Labels[container.KubeKeyContainerName],
		Image:     wl.Image,
		Digest:    digest,
	}
	dtrackPodMutex.Lock()
	p, ok := dtrackPods[wl.Domain+"/"+podName]
	dtrackPodMutex.Unlock()
	if !ok {
		return nil, errDtrackPodUnknown
	}
	v.ReplicaSet, v.PodLabels = p.ownerName, p.labels
	if d := getDomainData(wl.Domain); d != nil {
		v.NsLabels = d.Labels
	}

	proj, err := dtrack.Render(cfg, v)
	if err != nil {
		return nil, err
	}
	meta := sbom.Meta{Source: sbom.SourceContainer, Name: podName, ID: id, Domain: wl.Domain, Cluster: cluster, Digest: wl.ImageDigest}
	imageID := wl.ImageID
	return &dtrack.Item{ID: id, Project: proj, Digest: digest, BOM: func() ([]byte, error) {
		modules, baseOS, err := dtrackModules(id)
		if err != nil {
			return nil, err
		}
		var imgModules []*share.ScanModule
		if imageID != "" {
			if m, sum, err := scan.RegistryImageModules(imageID); err == nil && sum != nil {
				if m == nil { // a scan without modules exists: everything in the container is runtime
					m = []*share.ScanModule{}
				}
				imgModules = m
			}
		}
		meta.Created = time.Now().UTC()
		meta.Serial = uuid.New().String()
		var buf bytes.Buffer
		if err := sbom.Write(&buf, sbom.FormatCycloneDX, meta, sbom.Components(modules, baseOS, imgModules)); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}}, nil
}

// dtrackScanDone queues the SBOM of a scanned container. It never blocks scanning.
func dtrackScanDone(id string) {
	u, cfg, _, _ := dtrackState()
	if u == nil || !isLeader() {
		return
	}
	it, err := dtrackItem(id, cfg)
	if errors.Is(err, errDtrackPodUnknown) {
		log.WithFields(log.Fields{"workload": id}).Debug("dtrack: pod not known yet, the sweep uploads it later")
		return
	} else if err != nil {
		log.WithFields(log.Fields{"workload": id, "error": err}).Warn("no upload to Dependency-Track: " + dtrackReason(err))
		return
	}
	if it != nil {
		u.Enqueue(*it)
	}
}

func dtrackReason(err error) string {
	if errors.Is(err, dtrack.ErrEmptySymbol) {
		return "template symbol has no value"
	}
	return "cannot render project"
}

// dtrackLeaderLost drops the queue and the retries, so that only the new leader uploads.
func dtrackLeaderLost() {
	if u, _, _, _ := dtrackState(); u != nil {
		u.Reset()
	}
}

func dtrackSweepLoop() {
	t := time.NewTicker(dtrackSweepInterval)
	defer t.Stop()
	for range t.C {
		dtrackSweep(time.Now())
	}
}

// dtrackSweep queues all scanned running containers and deactivates projects that are gone.
func dtrackSweep(now time.Time) {
	u, cfg, startedAt, ctx := dtrackState()
	if u == nil {
		return
	}
	if !isLeader() {
		u.Reset()
		return
	}

	// every running container keeps its project alive; only a successful scan gives an SBOM to send
	scanned := make(map[string]bool)
	scanMutexRLock()
	for id, info := range scanMap {
		if info.objType == share.ScanObjectType_CONTAINER {
			scanned[id] = info.lastResult == share.ScanErrorCode_ScanErrNone && !info.lastScanTime.IsZero()
		}
	}
	scanMutexRUnlock()

	var items []dtrack.Item
	for id, ok := range scanned {
		it, err := dtrackItem(id, cfg)
		if err != nil {
			log.WithFields(log.Fields{"workload": id, "error": err}).Debug("dtrack: workload skipped")
			continue
		}
		if it != nil {
			if !ok {
				it.BOM = nil // failed scan: mark the project as seen only
			}
			items = append(items, *it)
		}
	}

	grace := dtrackGrace(cfg)
	// Only the leader, after the full cache sync and after the grace period, can tell that a project is really gone.
	canDeactivate := syncInitDone && now.Sub(cacher.leaderElectedAt) > grace && now.Sub(startedAt) > grace
	u.Sweep(ctx, items, grace, canDeactivate)
}
