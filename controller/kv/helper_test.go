package kv

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func randStr(r *rand.Rand, n int) string {
	b := make([]byte, n)
	r.Read(b)
	return fmt.Sprintf("%x", b)
}

func testReport() *share.CLUSScanReport {
	r := rand.New(rand.NewSource(1))
	rpt := &share.CLUSScanReport{}
	rpt.ImageID = "img1"
	rpt.Vuls = []*share.ScanVulnerability{{Name: "CVE-1", Description: randStr(r, 50)}}
	for i := 0; i < 20; i++ {
		rpt.Modules = append(rpt.Modules, &share.ScanModule{
			Name: fmt.Sprintf("nv%d", i), Version: "1", Source: "s",
			Vuls:     []*share.ScanModuleVul{{Name: "CVE-1"}},
			Purl:     "pkg:" + randStr(r, 40),
			Licenses: []string{randStr(r, 40)},
		})
	}
	for i := 0; i < 20; i++ {
		rpt.Modules = append(rpt.Modules, &share.ScanModule{
			Name: fmt.Sprintf("sy%d", i), Version: "1", Origin: "syft",
			Purl: "pkg:" + randStr(r, 40), Licenses: []string{randStr(r, 40)},
		})
	}
	return rpt
}

func decodeReport(t *testing.T, zb []byte) *share.CLUSScanReport {
	b := utils.GunzipBytes(zb)
	require.NotNil(t, b)
	var out share.CLUSScanReport
	require.NoError(t, gob.NewDecoder(bytes.NewReader(b)).Decode(&out))
	return &out
}

func encSize(t *testing.T, rpt *share.CLUSScanReport) int {
	zb, err := encodeScanReport(rpt, 1<<30)
	require.NoError(t, err)
	return len(zb)
}

func TestEncodeScanReport(t *testing.T) {
	full := testReport()
	fullSize := encSize(t, full)

	// reports with each step applied, to compute limits
	build := func(syft, lic, purl bool) *share.CLUSScanReport {
		rpt := testReport()
		var mods []*share.ScanModule
		for _, m := range rpt.Modules {
			if !syft && m.Origin == "syft" {
				continue
			}
			if !lic {
				m.Licenses = nil
			}
			if !purl {
				m.Purl = ""
			}
			mods = append(mods, m)
		}
		rpt.Modules = mods
		return rpt
	}
	noSyft := encSize(t, build(false, true, true))
	noLic := encSize(t, build(false, false, true))
	noPurl := encSize(t, build(false, false, false))
	require.True(t, fullSize > noSyft && noSyft > noLic && noLic > noPurl)

	cases := []struct {
		name            string
		limit           int
		syft, lic, purl bool // expected to be kept
	}{
		{"fits", fullSize + 1, true, true, true},
		{"step1", fullSize, false, true, true},
		{"step2", noSyft, false, false, true},
		{"step3", noLic, false, false, false},
		{"too small", 1, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := testReport()
			before := testReport()
			zb, err := encodeScanReport(in, c.limit)
			require.NoError(t, err)
			require.NotNil(t, zb)
			if c.name != "too small" {
				assert.Less(t, len(zb), c.limit)
			}

			out := decodeReport(t, zb)
			assert.Equal(t, in.Vuls, out.Vuls)
			nv, syft := 0, 0
			for _, m := range out.Modules {
				if m.Origin == "syft" {
					syft++
					continue
				}
				nv++
				assert.Equal(t, c.lic, len(m.Licenses) > 0)
				assert.Equal(t, c.purl, m.Purl != "")
				assert.NotEmpty(t, m.Name)
				assert.Len(t, m.Vuls, 1)
			}
			assert.Equal(t, 20, nv)
			assert.Equal(t, c.syft, syft == 20)
			if !c.syft {
				assert.Zero(t, syft)
			}

			// input must not change
			assert.Equal(t, before, in)
		})
	}
}

func TestEncodeScanReportDropsFullSBOM(t *testing.T) {
	rpt := testReport()
	rpt.FullSBOM, rpt.FullSBOMFormat = []byte("gz"), share.FullSBOMFormatCycloneDX
	for _, limit := range []int{1 << 30, 1} { // plain and size-limited path
		zb, err := encodeScanReport(rpt, limit)
		require.NoError(t, err)
		out := decodeReport(t, zb)
		require.Nil(t, out.FullSBOM)
		require.Empty(t, out.FullSBOMFormat)
	}
	require.NotNil(t, rpt.FullSBOM) // caller data untouched
}
