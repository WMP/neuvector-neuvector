package sbom

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func writeCycloneDX(w io.Writer, meta Meta, comps []Component) error {
	rootType := cdx.ComponentTypeContainer
	if meta.Source == SourceHost {
		rootType = cdx.ComponentTypeOS
	}
	root := cdx.Component{BOMRef: "root", Type: rootType, Name: meta.Name}
	var props []cdx.Property
	for _, p := range [][2]string{
		{"neuvector:source", meta.Source}, {"neuvector:cluster", meta.Cluster}, {"neuvector:id", meta.ID},
		{"neuvector:namespace", meta.Domain}, {"neuvector:digest", meta.Digest},
	} {
		if p[1] != "" {
			props = append(props, cdx.Property{Name: p[0], Value: p[1]})
		}
	}
	if len(props) > 0 {
		root.Properties = &props
	}
	if hex := parseDigest(meta.Digest); hex != "" {
		root.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hex}}
	}

	list := make([]cdx.Component, len(comps))
	for i, c := range comps {
		list[i] = cdx.Component{
			BOMRef: "pkg-" + strconv.Itoa(i+1), Type: cdx.ComponentTypeLibrary,
			Name: c.Name, Version: c.Version, PackageURL: c.Purl, Licenses: cdxLicenses(c.Licenses),
		}
		if c.Runtime {
			list[i].Properties = &[]cdx.Property{{Name: "neuvector:runtime", Value: "true"}}
		}
	}

	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + meta.Serial
	bom.Metadata = &cdx.Metadata{
		Timestamp: meta.Created.UTC().Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "NeuVector"}}},
		Component: &root,
	}
	bom.Components = &list

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encode CycloneDX: %w", err)
	}
	return nil
}

// cdxLicenses returns nil for no licenses. The schema allows either a list of
// license objects or exactly one expression.
func cdxLicenses(lics []string) *cdx.Licenses {
	if len(lics) == 0 {
		return nil
	}
	if expr, ok := andExpression(lics); ok && len(lics) > 1 {
		return &cdx.Licenses{{Expression: expr}}
	}
	var out cdx.Licenses
	for _, l := range lics {
		kind, norm := classifyLicense(l)
		switch {
		case kind == licenseExpr && len(lics) == 1:
			out = append(out, cdx.LicenseChoice{Expression: norm})
		case kind == licenseID && licenseRefRe.MatchString(norm):
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: norm}})
		case kind == licenseID:
			out = append(out, cdx.LicenseChoice{License: &cdx.License{ID: norm}})
		default:
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: l}})
		}
	}
	return &out
}

// andExpression joins licenses into one SPDX AND expression, as the SPDX writer does.
// ok is false when a license is free text or none is a compound expression.
func andExpression(lics []string) (string, bool) {
	parts := make([]string, len(lics))
	hasExpr := false
	for i, l := range lics {
		kind, norm := classifyLicense(l)
		switch kind {
		case licenseText:
			return "", false
		case licenseExpr:
			hasExpr = true
			norm = "(" + norm + ")"
		}
		parts[i] = norm
	}
	return strings.Join(parts, " AND "), hasExpr
}
