package scan

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/share"
)

// storeFullSBOM uploads the full SBOM of a registry scan to S3 and always drops it from the result,
// so it never reaches the cluster store. S3 errors never fail a scan.
func storeFullSBOM(result *share.ScanResult) {
	data, format := result.FullSBOM, result.FullSBOMFormat
	result.FullSBOM, result.FullSBOMFormat = nil, ""
	if len(data) == 0 {
		return
	}
	st := s3store.Current()
	if st == nil {
		log.Debug("sbom s3: storage disabled, full SBOM dropped")
		return
	}
	fields := log.Fields{"digest": result.Digest, "format": format}
	if result.Error != share.ScanErrorCode_ScanErrNone {
		return
	}
	if format != share.FullSBOMFormatCycloneDX || !s3store.ValidDigest(result.Digest) || len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		log.WithFields(fields).Warn("sbom s3: unexpected full SBOM format, digest or encoding, dropped")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := st.Put(ctx, result.Digest, data); err != nil {
		log.WithFields(log.Fields{"digest": result.Digest, "error": err}).Warn("sbom s3: upload failed")
		return
	}
	log.WithFields(log.Fields{"digest": result.Digest, "size": len(data)}).Info("sbom s3: full SBOM stored")
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
