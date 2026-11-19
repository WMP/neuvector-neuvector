package scan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/controller/sbom/s3store/s3fake"
	"github.com/neuvector/neuvector/share"
)

var testDigest = "sha256:" + strings.Repeat("a", 64)

func configS3(t *testing.T, srv *s3fake.Server, enabled bool) {
	s3store.Configure(&share.CLUSSystemConfig{ClusterName: "c1", SBOMStorage: share.CLUSSBOMStorage{
		Enabled: enabled, Endpoint: srv.URL, PathStyle: true, Bucket: "bkt", AccessKey: "ak", SecretKey: "sk",
	}})
	t.Cleanup(func() { s3store.Configure(&share.CLUSSystemConfig{ClusterName: "c1"}) })
}

// store runs the upload synchronously, as the scan task would in a goroutine.
func store(r *share.ScanResult) {
	if up := takeFullSBOM(r, "reg1", "img1", r.Digest); up != nil {
		up()
	}
}

func sbomResult(digest, format string, data []byte) *share.ScanResult {
	return &share.ScanResult{Digest: digest, FullSBOM: data, FullSBOMFormat: format}
}

var gz = []byte{0x1f, 0x8b, 1, 2, 3}

func TestStoreFullSBOM(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	configS3(t, srv, true)
	require.NotNil(t, s3store.Current())

	r := sbomResult(testDigest, share.FullSBOMFormatCycloneDX, gz)
	store(r)
	require.Nil(t, r.FullSBOM)
	require.Empty(t, r.FullSBOMFormat)
	require.Equal(t, map[string][]byte{"c1/images/" + testDigest + ".cdx.json.gz": gz}, srv.Objects())

	// S3 failure never fails the scan
	srv.SetFail(true)
	r = sbomResult(testDigest, share.FullSBOMFormatCycloneDX, gz)
	store(r)
	require.Nil(t, r.FullSBOM)
}

func TestStoreFullSBOMRejected(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	configS3(t, srv, true)

	for name, r := range map[string]*share.ScanResult{
		"bad digest":  sbomResult("../x", share.FullSBOMFormatCycloneDX, gz),
		"bad format":  sbomResult(testDigest, "spdx", gz),
		"not gzip":    sbomResult(testDigest, share.FullSBOMFormatCycloneDX, []byte("{}")),
		"scan failed": {Digest: testDigest, Error: share.ScanErrorCode_ScanErrNetwork, FullSBOM: gz, FullSBOMFormat: share.FullSBOMFormatCycloneDX},
	} {
		store(r)
		require.Nil(t, r.FullSBOM, name)
		require.Empty(t, r.FullSBOMFormat, name)
	}
	require.Empty(t, srv.Objects())
	require.Zero(t, srv.Requests())
}

func TestStoreFullSBOMDisabled(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	configS3(t, srv, false)
	require.Nil(t, s3store.Current()) // IncludeFullSBOM is false

	r := sbomResult(testDigest, share.FullSBOMFormatCycloneDX, gz)
	store(r)
	require.Nil(t, r.FullSBOM)
	require.Zero(t, srv.Requests())
}

func TestStoreFullSBOMDropped(t *testing.T) {
	srv := s3fake.New()
	defer srv.Close()
	configS3(t, srv, true)

	// the tag moved between the listing and the scan
	r := sbomResult("sha256:"+strings.Repeat("b", 64), share.FullSBOMFormatCycloneDX, gz)
	require.Nil(t, takeFullSBOM(r, "reg1", "img1", testDigest))
	require.Nil(t, r.FullSBOM)

	// too large
	big := make([]byte, s3store.MaxObjectSize+1)
	big[0], big[1] = 0x1f, 0x8b
	require.Nil(t, takeFullSBOM(sbomResult(testDigest, share.FullSBOMFormatCycloneDX, big), "reg1", "img1", testDigest))

	// storage changed after the scan: the old store is not used
	up := takeFullSBOM(sbomResult(testDigest, share.FullSBOMFormatCycloneDX, gz), "reg1", "img1", testDigest)
	require.NotNil(t, up)
	configS3(t, srv, false)
	up()
	require.Zero(t, srv.Requests())
}
