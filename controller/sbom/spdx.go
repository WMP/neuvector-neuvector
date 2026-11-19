package sbom

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

var nonIDChars = regexp.MustCompile(`[^A-Za-z0-9.-]`)

// licenseRefs assigns LicenseRef IDs to free-text licenses and collects the
// document-level extracted licensing infos.
type licenseRefs struct {
	ids   map[string]string // free text -> LicenseRef ID
	used  map[string]bool
	infos []*spdx.OtherLicense
}

func (r *licenseRefs) define(id, text string) {
	r.used[id] = true
	r.infos = append(r.infos, &spdx.OtherLicense{LicenseIdentifier: id, ExtractedText: text, LicenseName: text})
}

// declared returns the licenseDeclared value for a package.
func (r *licenseRefs) declared(lics []string) string {
	if len(lics) == 0 {
		return "NOASSERTION"
	}
	parts := make([]string, len(lics))
	for i, l := range lics {
		kind, norm := classifyLicense(l)
		if kind == licenseText {
			id, ok := r.ids[l]
			if !ok {
				base := "LicenseRef-" + nonIDChars.ReplaceAllString(l, "-")
				id = base
				for n := 2; r.used[id]; n++ { // different texts can sanitize to the same ID
					id = base + "-" + strconv.Itoa(n)
				}
				r.ids[l] = id
				r.define(id, l)
			}
			norm = id
		} else {
			for _, ref := range licenseRefFind.FindAllString(norm, -1) {
				if !r.used[ref] {
					r.define(ref, ref) // no text is known for a bare LicenseRef
				}
			}
		}
		if kind == licenseExpr && len(lics) > 1 {
			norm = "(" + norm + ")"
		}
		parts[i] = norm
	}
	return strings.Join(parts, " AND ")
}

func writeSPDX(w io.Writer, meta Meta, comps []Component) error {
	name := meta.Name
	if name == "" {
		name = meta.ID
	}
	var info []string
	for _, p := range [][2]string{
		{"source", meta.Source}, {"cluster", meta.Cluster}, {"id", meta.ID},
		{"namespace", meta.Domain}, {"digest", meta.Digest},
	} {
		if p[1] != "" {
			info = append(info, p[0]+": "+p[1])
		}
	}

	purpose := "CONTAINER"
	if meta.Source == SourceHost {
		purpose = "OPERATING_SYSTEM"
	}
	root := &spdx.Package{
		PackageName: name, PackageSPDXIdentifier: "root", PackageDownloadLocation: "NOASSERTION",
		PrimaryPackagePurpose: purpose,
	}
	if hex := parseDigest(meta.Digest); hex != "" {
		root.PackageChecksums = []common.Checksum{{Algorithm: common.SHA256, Value: hex}}
	}

	doc := &spdx.Document{
		SPDXVersion: spdx.Version, DataLicense: spdx.DataLicense, SPDXIdentifier: "DOCUMENT",
		DocumentName: name, DocumentNamespace: "https://neuvector.com/spdx/" + meta.Serial,
		CreationInfo: &spdx.CreationInfo{
			Creators:       []common.Creator{{Creator: "NeuVector", CreatorType: "Tool"}},
			Created:        meta.Created.UTC().Format("2006-01-02T15:04:05Z"),
			CreatorComment: strings.Join(info, ", "),
		},
		Packages: []*spdx.Package{root},
		Relationships: []*spdx.Relationship{{
			RefA: common.MakeDocElementID("", "DOCUMENT"), RefB: common.MakeDocElementID("", "root"),
			Relationship: common.TypeRelationshipDescribe,
		}},
	}

	refs := &licenseRefs{ids: map[string]string{}, used: map[string]bool{}}
	for i, c := range comps {
		p := &spdx.Package{
			PackageName: c.Name, PackageSPDXIdentifier: common.ElementID("Package-" + strconv.Itoa(i+1)),
			PackageVersion: c.Version, PackageDownloadLocation: "NOASSERTION",
			PackageLicenseConcluded: "NOASSERTION", PackageLicenseDeclared: refs.declared(c.Licenses),
			PackageCopyrightText: "NOASSERTION",
		}
		if c.Purl != "" {
			p.PackageExternalReferences = []*spdx.PackageExternalReference{
				{Category: common.CategoryPackageManager, RefType: common.TypePackageManagerPURL, Locator: c.Purl},
			}
		}
		if c.Runtime {
			p.PackageComment = "runtime: found in the running container only"
		}
		doc.Packages = append(doc.Packages, p)
		doc.Relationships = append(doc.Relationships, &spdx.Relationship{
			RefA: common.MakeDocElementID("", "root"), RefB: common.MakeDocElementID("", string(p.PackageSPDXIdentifier)),
			Relationship: common.TypeRelationshipContains,
		})
	}
	doc.OtherLicenses = refs.infos

	if err := spdxjson.Write(doc, w, spdxjson.Indent("  ")); err != nil {
		return fmt.Errorf("encode SPDX: %w", err)
	}
	return nil
}
