package rest

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/sbom"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

const (
	componentMaxName    = 256
	componentMaxPurl    = 512
	componentMaxVersion = 128
)

// componentSearchLock allows one search at a time: a search reads the modules of every scanned object.
var componentSearchLock sync.Mutex

type componentQuery struct {
	name    string
	purlKey string // PurlMergeKey of the query purl
	version sbom.VersionQuery
}

// purlKeyName returns the name of a merge key "type/namespace/name@version".
func purlKeyName(key string) string {
	if i := strings.LastIndex(key, "@"); i >= 0 {
		key = key[:i]
	}
	return key[strings.LastIndex(key, "/")+1:]
}

func (q *componentQuery) match(c sbom.Component) bool {
	key := scanUtils.PurlMergeKey(c.Purl)
	if q.name != "" && !strings.EqualFold(q.name, c.Name) && !strings.EqualFold(q.name, purlKeyName(key)) {
		return false
	}
	if q.purlKey != "" {
		if strings.HasSuffix(q.purlKey, "@") { // no version in the query: all versions
			if key == "" || !strings.HasPrefix(key, q.purlKey) {
				return false
			}
		} else if key != q.purlKey {
			return false
		}
	}
	if q.version != nil {
		typ, _, _ := strings.Cut(key, "/")
		return q.version.Match(typ, c.Version)
	}
	return true
}

// find returns the components of the modules that match the query.
func (q *componentQuery) find(modules []*share.ScanModule, baseOS string) []api.RESTComponent {
	var out []api.RESTComponent
	for _, c := range sbom.Components(modules, baseOS, nil) {
		if q.match(c) {
			out = append(out, api.RESTComponent{Name: c.Name, Version: c.Version, Purl: c.Purl})
		}
	}
	return out
}

func parseComponentQuery(r *http.Request) (*componentQuery, string) {
	v := r.URL.Query()
	q := &componentQuery{name: strings.TrimSpace(v.Get("name"))}
	purl, version := strings.TrimSpace(v.Get("purl")), strings.TrimSpace(v.Get("version"))
	if len(q.name) > componentMaxName || len(purl) > componentMaxPurl || len(version) > componentMaxVersion {
		return nil, "A query parameter is too long"
	}
	if q.name == "" && purl == "" {
		return nil, "The name or purl parameter is required"
	}
	if purl != "" {
		if q.purlKey = scanUtils.PurlMergeKey(purl); q.purlKey == "" {
			return nil, "Invalid purl"
		}
	}
	if version != "" {
		var err error
		if q.version, err = sbom.ParseVersionQuery(version); err != nil {
			return nil, "Invalid version: " + err.Error()
		}
	}
	return q, ""
}

func addComponents(list []api.RESTComponent, add []api.RESTComponent) []api.RESTComponent {
	for _, c := range add {
		if !slices.Contains(list, c) {
			list = append(list, c)
		}
	}
	return list
}

// scanModulesOrSkip returns ok=false when the object has no usable scan.
func scanModulesOrSkip(id string) ([]*share.ScanModule, string, bool) {
	modules, baseOS, err := cacher.GetScanModules(id)
	if err != nil {
		if !errors.Is(err, common.ErrObjectNotFound) {
			log.WithFields(log.Fields{"id": id, "error": err}).Error("Failed to get scan modules")
		}
		return nil, "", false
	}
	return modules, baseOS, true
}

func searchComponentRegistryImages(r *http.Request, q *componentQuery, acc *access.AccessControl) []*api.RESTComponentRegistryImage {
	names := []string{common.RegistryRepoScanName, common.RegistryFedRepoScanName}
	for _, s := range scanner.GetAllRegistrySummary(share.ScopeAll, acc) {
		names = append(names, s.Name)
	}
	slices.Sort(names)
	names = slices.Compact(names)

	list := make([]*api.RESTComponentRegistryImage, 0)
	for _, name := range names {
		var ids []string
		for _, row := range scanner.GetRegistryImageSummary(name, nil, acc) {
			ids = append(ids, row.ImageID)
		}
		slices.Sort(ids)
		for _, id := range slices.Compact(ids) {
			if r.Context().Err() != nil {
				return list
			}
			modules, sum, err := scanner.GetRegistryImageModules(name, id, acc)
			if err != nil || sum == nil {
				if err != nil && !errors.Is(err, common.ErrObjectNotFound) && !errors.Is(err, common.ErrObjectAccessDenied) {
					log.WithFields(log.Fields{"registry": name, "id": id, "error": err}).Error("Failed to get scan modules")
				}
				continue
			}
			comps := q.find(modules, sum.BaseOS)
			if len(comps) == 0 {
				continue
			}
			img := &api.RESTComponentRegistryImage{Registry: name, ImageID: id, Digest: sum.Digest, Images: []string{}, Components: comps}
			for _, i := range sum.Images {
				// the summary is visible when one of its domains is; hide the tags of the other domains
				if i.Domain != "" && !acc.Authorize(&share.CLUSWorkload{Domain: i.Domain}, nil) {
					continue
				}
				ref := i.Repo
				if i.Tag != "" {
					ref += ":" + i.Tag
				}
				img.Images = append(img.Images, ref)
				if img.Domain == "" {
					img.Domain = i.Domain
				}
			}
			slices.Sort(img.Images)
			list = append(list, img)
		}
	}
	slices.SortFunc(list, func(a, b *api.RESTComponentRegistryImage) int {
		return strings.Compare(a.Registry+"\x00"+a.ImageID, b.Registry+"\x00"+b.ImageID)
	})
	return list
}

func handlerScanComponent(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}
	q, msg := parseComponentQuery(r)
	if q == nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}
	if !componentSearchLock.TryLock() {
		restRespErrorMessage(w, http.StatusTooManyRequests, api.RESTErrOpNotAllowed, "Another component search is running")
		return
	}
	defer componentSearchLock.Unlock()

	resp := api.RESTComponentSearchData{
		Workloads:     make([]*api.RESTComponentWorkload, 0),
		Hosts:         make([]*api.RESTComponentHost, 0),
		RunningImages: make([]*api.RESTComponentRunningImage, 0),
	}

	running := map[string]*api.RESTComponentRunningImage{}
	for _, wl := range cacher.GetAllWorkloadsBrief("", acc) {
		if r.Context().Err() != nil {
			return
		}
		if wl.State == api.WorkloadStateExit {
			continue
		}
		modules, baseOS, ok := scanModulesOrSkip(wl.ID)
		if !ok {
			continue
		}
		comps := q.find(modules, baseOS)
		if len(comps) == 0 {
			continue
		}
		name := wl.PodName
		if name == "" {
			name = wl.DisplayName
		}
		if name == "" {
			name = wl.Name
		}
		resp.Workloads = append(resp.Workloads, &api.RESTComponentWorkload{
			ID: wl.ID, Name: name, Container: wl.DisplayName, Domain: wl.Domain, Image: wl.Image, ImageID: wl.ImageID, Components: comps})
		if wl.ImageID != "" {
			ri := running[wl.ImageID]
			if ri == nil {
				ri = &api.RESTComponentRunningImage{ImageID: wl.ImageID, Image: wl.Image}
				running[wl.ImageID] = ri
			}
			if wl.Image < ri.Image { // the cache order is random: give a stable name
				ri.Image = wl.Image
			}
			ri.Workloads++
			ri.Components = addComponents(ri.Components, comps)
		}
	}
	for _, ri := range running {
		slices.SortFunc(ri.Components, func(a, b api.RESTComponent) int {
			return strings.Compare(a.Name+"\x00"+a.Version+"\x00"+a.Purl, b.Name+"\x00"+b.Version+"\x00"+b.Purl)
		})
		resp.RunningImages = append(resp.RunningImages, ri)
	}

	for _, host := range cacher.GetAllHosts(acc) {
		if r.Context().Err() != nil {
			return
		}
		if modules, baseOS, ok := scanModulesOrSkip(host.ID); ok {
			if comps := q.find(modules, baseOS); len(comps) > 0 {
				resp.Hosts = append(resp.Hosts, &api.RESTComponentHost{ID: host.ID, Name: host.Name, Components: comps})
			}
		}
	}

	resp.Images = searchComponentRegistryImages(r, q, acc)
	if r.Context().Err() != nil {
		return
	}

	slices.SortFunc(resp.Workloads, func(a, b *api.RESTComponentWorkload) int {
		return strings.Compare(a.Domain+"\x00"+a.Name+"\x00"+a.Container+"\x00"+a.ID, b.Domain+"\x00"+b.Name+"\x00"+b.Container+"\x00"+b.ID)
	})
	slices.SortFunc(resp.Hosts, func(a, b *api.RESTComponentHost) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(resp.RunningImages, func(a, b *api.RESTComponentRunningImage) int {
		return strings.Compare(a.Image+"\x00"+a.ImageID, b.Image+"\x00"+b.ImageID)
	})
	restRespSuccess(w, r, &resp, acc, login, nil, "Search component")
}
