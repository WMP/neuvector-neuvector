// Package sbom generates CycloneDX 1.6 JSON and SPDX 2.3 JSON documents from scan modules.
package sbom

import (
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

const (
	FormatCycloneDX = "cyclonedx"
	FormatSPDX      = "spdx"

	SourceContainer = "running container"
	SourceImage     = "image"
	SourceHost      = "host"
)

var ErrUnknownFormat = errors.New("unknown SBOM format")

// Meta describes the scanned object.
type Meta struct {
	Source  string    // SourceContainer, SourceImage or SourceHost
	Name    string    // workload, image (repo:tag) or host name
	ID      string    // workload, image or host ID
	Domain  string    // Kubernetes namespace of a workload, "" otherwise
	Cluster string    // cluster name
	Digest  string    // image digest ("sha256:..."), "" when unknown
	Created time.Time // document creation time
	Serial  string    // UUID, unique per document (CycloneDX serialNumber, SPDX documentNamespace)
}

// Component is one SBOM component.
type Component struct {
	Name     string
	Version  string
	Purl     string   // "" when the module has no valid purl
	Licenses []string // SPDX license IDs, SPDX expressions or free-text names
	Runtime  bool     // found in the running container only, not in the image scan
}

// ContentType returns the HTTP content type of format. ok is false for an unknown format.
func ContentType(format string) (ct string, ok bool) {
	switch format {
	case FormatCycloneDX:
		return "application/vnd.cyclonedx+json", true
	case FormatSPDX:
		return "application/spdx+json", true
	}
	return "", false
}

// Components converts scan modules to SBOM components. namespace is
// ScanResult.Namespace (e.g. "debian:12"), used for purl. image holds the
// modules of the image scan of the same image; when it is not nil, components
// that are not in it get Runtime=true and licenses from it are added.
func Components(modules []*share.ScanModule, namespace string, image []*share.ScanModule) []Component {
	// NeuVector adds some OS packages a second time as application modules for CVE matching.
	osNames := map[string]bool{}
	for _, m := range modules {
		if isOSModule(m) {
			upstream, bin, _ := strings.Cut(m.Name, "/") // deb "upstream/binary"
			osNames[osPackageName(upstream)] = true
			osNames[osPackageName(bin)] = true
		}
	}

	type key struct{ source, name, version string }
	mkKey := func(m *share.ScanModule) key { return key{m.Source, m.Name, m.Version} }
	imageLicenses := map[key][]string{}
	for _, m := range image {
		imageLicenses[mkKey(m)] = append(imageLicenses[mkKey(m)], m.Licenses...)
	}

	var comps []*Component
	byKey := map[key]*Component{}
	for _, m := range modules {
		switch m.Source {
		case "nginx", "openssl", "busybox":
			if osNames[osPackageName(m.Name)] {
				continue
			}
		}
		c := byKey[mkKey(m)]
		if c == nil {
			c = &Component{Name: componentName(m), Version: m.Version, Purl: scanUtils.ModulePurl(m, namespace)}
			if image != nil {
				lic, found := imageLicenses[mkKey(m)]
				c.Runtime = !found
				c.Licenses = append(c.Licenses, lic...)
			}
			byKey[mkKey(m)] = c
			comps = append(comps, c)
		}
		c.Licenses = append(c.Licenses, m.Licenses...)
	}

	out := make([]Component, len(comps))
	for i, c := range comps {
		c.Licenses = sortedUnique(c.Licenses)
		out[i] = *c
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Purl < b.Purl
	})
	return out
}

func isOSModule(m *share.ScanModule) bool {
	return m.Source == "" || strings.Contains(m.Source, ":")
}

// componentName matches the name in the purl (scanUtils.ModulePurl): OS packages use the
// binary name of "upstream/binary" and "openssl" for "opensslxx"; applications lose the NeuVector prefix.
func componentName(m *share.ScanModule) string {
	if isOSModule(m) {
		if _, bin, ok := strings.Cut(m.Name, "/"); ok && bin != "" {
			return bin
		}
		return osPackageName(m.Name)
	}
	return stripEcosystem(m.Name)
}

func osPackageName(name string) string {
	if name == "opensslxx" {
		return "openssl"
	}
	return name
}

var ecosystemPrefixes = []string{"python:", "go:", "ruby:", ".NET:", "php:", "r:"}

func stripEcosystem(name string) string {
	for _, p := range ecosystemPrefixes {
		if rest, ok := strings.CutPrefix(name, p); ok && rest != "" {
			return rest
		}
	}
	return name
}

// sortedUnique trims, drops empty strings and duplicates, and sorts. It returns nil for no result.
func sortedUnique(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Write encodes the SBOM in format to w. It returns ErrUnknownFormat for an unknown format.
func Write(w io.Writer, format string, meta Meta, comps []Component) error {
	switch format {
	case FormatCycloneDX:
		return writeCycloneDX(w, meta, comps)
	case FormatSPDX:
		return writeSPDX(w, meta, comps)
	}
	return ErrUnknownFormat
}

// parseDigest returns the hex part of "sha256:<64 hex>", or "".
func parseDigest(digest string) string {
	if hex, ok := strings.CutPrefix(digest, "sha256:"); ok && sha256Hex.MatchString(hex) {
		return hex
	}
	return ""
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
