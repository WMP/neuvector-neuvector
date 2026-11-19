package scan

import (
	"sort"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/common"
)

// RegistryImageRef is a registry image whose digest is in the requested set.
type RegistryImageRef struct {
	Registry string
	ImageID  string
	Digest   string
	Images   []string // sorted repo:tag
}

// GetRegistryImagesByDigest returns the registry images with a digest in the set that the user can access.
func (m *scanMethod) GetRegistryImagesByDigest(digests map[string]bool, acc *access.AccessControl) []RegistryImageRef {
	names := []string{common.RegistryRepoScanName, common.RegistryFedRepoScanName}
	for _, rs := range regMapToArray(true, true) {
		names = append(names, rs.config.Name)
	}

	refs := []RegistryImageRef{}
	for _, n := range names {
		rs, err := resolveRegistry(n, acc)
		if err != nil || rs == nil { // repo scan registries can be nil before init
			continue
		}
		func() {
			rs.stateLock()
			defer rs.stateUnlock()
			for id, sum := range rs.summary {
				if sum.Digest == "" || !digests[sum.Digest] {
					continue
				}
				if _, err := authorizeRegistryImage(rs, id, acc); err != nil {
					continue
				}
				ref := RegistryImageRef{Registry: n, ImageID: id, Digest: sum.Digest, Images: []string{}}
				for _, img := range sum.Images {
					if img.Repo == "" {
						continue
					}
					name := img.Repo
					if img.Tag != "" {
						name += ":" + img.Tag
					}
					ref.Images = append(ref.Images, name)
				}
				sort.Strings(ref.Images)
				refs = append(refs, ref)
			}
		}()
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Registry != refs[j].Registry {
			return refs[i].Registry < refs[j].Registry
		}
		return refs[i].ImageID < refs[j].ImageID
	})
	return refs
}
