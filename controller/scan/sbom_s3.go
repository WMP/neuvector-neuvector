package scan

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/share"
)

// takeFullSBOM drops the full SBOM from a registry scan result, so it never reaches the cluster store,
// and returns its upload, or nil. digest is the registry summary digest: REST and the cleanup look it up.
// S3 errors never fail a scan.
func takeFullSBOM(result *share.ScanResult, digest string) func() {
	data, format := result.FullSBOM, result.FullSBOMFormat
	result.FullSBOM, result.FullSBOMFormat = nil, ""
	if len(data) == 0 || result.Error != share.ScanErrorCode_ScanErrNone {
		return nil
	}
	st := s3store.Current()
	if st == nil {
		log.Debug("sbom s3: storage disabled, full SBOM dropped")
		return nil
	}
	if format != share.FullSBOMFormatCycloneDX || !s3store.ValidDigest(digest) || len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		log.WithFields(log.Fields{"digest": digest, "format": format}).Warn("sbom s3: unexpected full SBOM format, digest or encoding, dropped")
		return nil
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := st.Put(ctx, digest, data); err != nil {
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
