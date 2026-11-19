package scan

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/share"
)

var sbomUploadSlots = make(chan struct{}, 4)

const sbomUploadWait = 2 * time.Minute

// takeFullSBOM drops the full SBOM from a registry scan result, so it never reaches the cluster store,
// and returns its upload, or nil. digest is the registry summary digest: REST and the cleanup look it up.
// S3 errors never fail a scan.
func takeFullSBOM(result *share.ScanResult, registry, imageID, digest string) func() {
	data, format := result.FullSBOM, result.FullSBOMFormat
	result.FullSBOM, result.FullSBOMFormat = nil, ""
	if len(data) == 0 || result.Error != share.ScanErrorCode_ScanErrNone || digest == "" {
		return nil
	}
	st := s3store.Current()
	if st == nil {
		log.Debug("sbom s3: storage disabled, full SBOM dropped")
		return nil
	}
	fields := log.Fields{"digest": digest, "scanned_digest": result.Digest, "format": format, "size": len(data)}
	if format != share.FullSBOMFormatCycloneDX || !s3store.ValidDigest(digest) || len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b ||
		len(data) > s3store.MaxObjectSize {
		log.WithFields(fields).Warn("sbom s3: unexpected full SBOM format, digest, encoding or size, dropped")
		return nil
	}
	if result.Digest != "" && result.Digest != digest { // the tag moved between the listing and the scan
		log.WithFields(fields).Warn("sbom s3: scanned image digest differs from the registry digest, dropped")
		return nil
	}
	return func() {
		// a slow S3 must not pile up uploads in memory: wait for a slot, then give up
		select {
		case sbomUploadSlots <- struct{}{}:
			defer func() { <-sbomUploadSlots }()
		case <-time.After(sbomUploadWait):
			log.WithFields(log.Fields{"digest": digest}).Warn("sbom s3: too many uploads in progress, full SBOM dropped")
			return
		}
		if s3store.Current() != st { // storage disabled or changed after the scan
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := st.Put(ctx, digest, registry, imageID, data); err != nil {
			log.WithFields(log.Fields{"digest": digest, "error": err}).Warn("sbom s3: upload failed")
			return
		}
		log.WithFields(log.Fields{"digest": digest, "size": len(data)}).Info("sbom s3: full SBOM stored")
	}
}

// RegistryImageDigests returns the digests of all registry and repo-scan images. No access control: internal use.
func RegistryImageDigests() map[string]bool {
	digests := make(map[string]bool)
	rss := append(regMapToArray(true, true), repoScanRegistry, repoFedScanRegistry)
	for _, rs := range rss {
		if rs == nil {
			continue
		}
		rs.stateLock()
		for _, sum := range rs.summary {
			if sum.Digest != "" {
				digests[sum.Digest] = true
			}
		}
		rs.stateUnlock()
	}
	return digests
}
