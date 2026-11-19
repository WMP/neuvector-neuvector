package sbom

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/neuvector/neuvector/share"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata")

func mod(source, name, version string, lics ...string) *share.ScanModule {
	return &share.ScanModule{Source: source, Name: name, Version: version, Licenses: lics}
}

// brief renders a component as "name@version[ runtime][ lic,lic]".
func brief(comps []Component) []string {
	out := []string{}
	for _, c := range comps {
		s := c.Name + "@" + c.Version
		if c.Runtime {
			s += " runtime"
		}
		if len(c.Licenses) > 0 {
			s += " " + strings.Join(c.Licenses, ",")
		}
		out = append(out, s)
	}
	return out
}

func TestComponents(t *testing.T) {
	const deb = "debian:12"
	syft := mod("jar", "org.apache.logging.log4j:log4j-core", "2.14.1")
	syft.Origin = "syft"

	tests := []struct {
		name    string
		modules []*share.ScanModule
		image   []*share.ScanModule
		want    []string
	}{
		{"prefix strip", []*share.ScanModule{
			mod("python", "python:requests", "2.31.0"), mod("gem", "ruby:rake", "13"), mod("nuget", ".NET:Foo", "1"),
			mod("go", "go:golang.org/x/net", "1"), mod("php", "php:a/b", "1"), mod("r", "r:ggplot2", "1"),
			mod("python", "python:", "1"), mod("npm", "go:lodash", "1"),
		}, nil, []string{"Foo@1", "a/b@1", "ggplot2@1", "golang.org/x/net@1", "lodash@1", "python:@1", "rake@13", "requests@2.31.0"}},
		{"nginx with OS module", []*share.ScanModule{mod(deb, "nginx", "1.22"), mod("nginx", "nginx", "1.22")}, nil,
			[]string{"nginx@1.22"}},
		{"nginx without OS module", []*share.ScanModule{mod("nginx", "nginx", "1.22")}, nil, []string{"nginx@1.22"}},
		{"openssl with empty-source OS module", []*share.ScanModule{mod("", "openssl", "3.0"), mod("openssl", "openssl", "3.0.1")}, nil,
			[]string{"openssl@3.0"}},
		{"opensslxx", []*share.ScanModule{mod(deb, "opensslxx", "3.0"), mod("openssl", "openssl", "3.0.1")}, nil,
			[]string{"openssl@3.0"}},
		{"deb upstream/binary", []*share.ScanModule{mod(deb, "openssl/libssl3", "3.0"), mod("openssl", "openssl", "3.0.1"), mod(deb, "glibc/libc6", "2.36")}, nil,
			[]string{"libc6@2.36", "libssl3@3.0"}},
		{"busybox", []*share.ScanModule{mod("busybox", "busybox", "1.36"), mod("alpine:3.18", "busybox", "1.36")}, nil,
			[]string{"busybox@1.36"}},
		{"exact duplicates", []*share.ScanModule{mod(deb, "bash", "5.2", "GPL-3.0-or-later"), mod(deb, "bash", "5.2", "MIT", "GPL-3.0-or-later")}, nil,
			[]string{"bash@5.2 GPL-3.0-or-later,MIT"}},
		{"same name, different source", []*share.ScanModule{mod("npm", "x", "1"), mod("python", "x", "1")}, nil,
			[]string{"x@1", "x@1"}},
		{"syft kept", []*share.ScanModule{syft}, nil, []string{"org.apache.logging.log4j:log4j-core@2.14.1"}},
		{"runtime and license enrichment",
			[]*share.ScanModule{mod(deb, "bash", "5.2", "MIT"), mod("npm", "lodash", "4.17.21"), syft},
			[]*share.ScanModule{mod(deb, "bash", "5.2", "GPL-3.0-or-later", "MIT"), mod(deb, "other", "1")},
			[]string{"bash@5.2 GPL-3.0-or-later,MIT", "lodash@4.17.21 runtime", "org.apache.logging.log4j:log4j-core@2.14.1 runtime"}},
		{"no image, no runtime", []*share.ScanModule{mod("npm", "lodash", "4.17.21")}, nil, []string{"lodash@4.17.21"}},
		{"sorting", []*share.ScanModule{mod("a", "b", "2"), mod("a", "b", "10"), mod("a", "a", "3"), mod("a", "python:c", "1")}, nil,
			[]string{"a@3", "b@10", "b@2", "c@1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := brief(Components(tc.modules, deb, tc.image))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestComponentsPurl(t *testing.T) {
	got := Components([]*share.ScanModule{mod("debian:12", "bash", "5.2"), mod("foo:1", "thing", "1")}, "debian:12", nil)
	if got[0].Name != "bash" || got[0].Purl == "" {
		t.Errorf("bash must have a purl: %+v", got[0])
	}
	if got[1].Name != "thing" || got[1].Purl != "" {
		t.Errorf("thing must have no purl: %+v", got[1])
	}
}

func TestClassifyLicense(t *testing.T) {
	tests := []struct {
		in   string
		kind licenseKind
		norm string
	}{
		{"mit", licenseID, "MIT"},
		{"apache-2.0", licenseID, "Apache-2.0"},
		{"BSD", licenseText, "BSD"},
		{"GPL v2", licenseText, "GPL v2"},
		{"LicenseRef-Foo.1", licenseID, "LicenseRef-Foo.1"},
		{"LicenseRef-bad_id", licenseText, "LicenseRef-bad_id"},
		{"MIT AND apache-2.0", licenseExpr, "MIT AND Apache-2.0"},
		{"mit or (gpl-2.0-only and bsd-3-clause)", licenseExpr, "MIT OR (GPL-2.0-only AND BSD-3-Clause)"},
		{"GPL-2.0-only WITH Classpath-exception-2.0", licenseExpr, "GPL-2.0-only WITH Classpath-exception-2.0"},
		{"GPL-2.0+ OR MIT", licenseExpr, "GPL-2.0+ OR MIT"},
		{"MIT AND", licenseText, "MIT AND"},
		{"MIT OR OR GPL-2.0-only", licenseText, "MIT OR OR GPL-2.0-only"},
		{"(MIT", licenseText, "(MIT"},
		{"MIT AND Foo", licenseText, "MIT AND Foo"},
		{"MIT GPL-2.0-only", licenseText, "MIT GPL-2.0-only"},
		{"  MIT  ", licenseID, "MIT"},
		{"apache-2.0+", licenseExpr, "Apache-2.0+"},
		{"(MIT)", licenseExpr, "(MIT)"},
		{"Foo+", licenseText, "Foo+"},
	}
	for _, tc := range tests {
		kind, norm := classifyLicense(tc.in)
		if kind != tc.kind || norm != tc.norm {
			t.Errorf("classifyLicense(%q) = %v, %q; want %v, %q", tc.in, kind, norm, tc.kind, tc.norm)
		}
	}
}

func TestSPDXLicenseRefs(t *testing.T) {
	r := &licenseRefs{ids: map[string]string{}, used: map[string]bool{}}
	if got := r.declared(nil); got != "NOASSERTION" {
		t.Errorf("no licenses: %q", got)
	}
	if got := r.declared([]string{"GPL v2", "GPL-v2", "MIT OR Apache-2.0"}); got != "LicenseRef-GPL-v2 AND LicenseRef-GPL-v2-2 AND (MIT OR Apache-2.0)" {
		t.Errorf("got %q", got)
	}
	if got := r.declared([]string{"GPL v2"}); got != "LicenseRef-GPL-v2" || len(r.infos) != 2 {
		t.Errorf("same text must reuse its ID: %q, %d infos", got, len(r.infos))
	}

	// a literal LicenseRef in a later component keeps its ID; free text gets another one
	r = &licenseRefs{ids: map[string]string{}, used: map[string]bool{}}
	comps := []Component{{Licenses: []string{"Foo Bar"}}, {Licenses: []string{"LicenseRef-Foo-Bar"}}}
	r.reserve(comps)
	if got := r.declared(comps[0].Licenses); got != "LicenseRef-Foo-Bar-2" {
		t.Errorf("free text after reserve: %q", got)
	}
	if got := r.declared(comps[1].Licenses); got != "LicenseRef-Foo-Bar" {
		t.Errorf("literal ref: %q", got)
	}
}

func TestContentType(t *testing.T) {
	for format, want := range map[string]string{FormatCycloneDX: "application/vnd.cyclonedx+json", FormatSPDX: "application/spdx+json"} {
		if got, ok := ContentType(format); !ok || got != want {
			t.Errorf("ContentType(%q) = %q, %v", format, got, ok)
		}
	}
	if _, ok := ContentType("xml"); ok {
		t.Error("unknown format must not be ok")
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "xml", Meta{}, nil); !errors.Is(err, ErrUnknownFormat) || buf.Len() != 0 {
		t.Errorf("err = %v, written %d bytes", err, buf.Len())
	}
}

func TestGolden(t *testing.T) {
	const deb = "debian:12"
	created := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	syft := mod("jar", "org.apache.logging.log4j:log4j-core", "2.14.1", "Apache-2.0")
	syft.Origin = "syft"
	nginxApp := mod("nginx", "nginx", "1.22.1")

	runtimeModules := []*share.ScanModule{
		mod(deb, "bash", "5.2.15-2", "GPL-3.0-or-later"),
		mod(deb, "openssl", "3.0.11-1", "Apache-2.0 AND OpenSSL"),
		mod(deb, "nginx", "1.22.1", "bsd-2-clause"),
		nginxApp,
		mod("npm", "lodash", "4.17.21", "MIT"),
		mod("python", "python:requests", "2.31.0", "Apache-2.0 OR MIT", "GPL v2", "GPL-v2", "BSD", "LicenseRef-Vendor.1"),
		mod("python", "python:requests", "2.31.0"),
		syft,
	}
	imageModules := []*share.ScanModule{
		mod(deb, "bash", "5.2.15-2", "GPL-3.0-or-later"),
		mod(deb, "openssl", "3.0.11-1"),
		mod(deb, "nginx", "1.22.1"),
		mod("python", "python:requests", "2.31.0"),
	}

	tests := []struct {
		file  string
		meta  Meta
		comps []Component
	}{
		{"container", Meta{
			Source: SourceContainer, Name: "web-1", ID: "0123456789ab", Domain: "shop", Cluster: "cluster.local",
			Digest: "sha256:" + strings.Repeat("ab", 32), Created: created, Serial: "11111111-2222-4333-8444-555555555555",
		}, Components(runtimeModules, deb, imageModules)},
		{"host", Meta{
			Source: SourceHost, Name: "node-1", ID: "host-id-1", Cluster: "cluster.local",
			Created: created, Serial: "11111111-2222-4333-8444-666666666666",
		}, Components([]*share.ScanModule{mod(deb, "bash", "5.2.15-2", "GPL-3.0-or-later")}, deb, nil)},
		{"empty", Meta{
			Source: SourceImage, Name: "nginx:1.22", ID: "img-1", Created: created, Serial: "11111111-2222-4333-8444-777777777777",
		}, nil},
	}
	exts := map[string]string{FormatCycloneDX: ".cdx.json", FormatSPDX: ".spdx.json"}
	for _, tc := range tests {
		for format, ext := range exts {
			t.Run(tc.file+ext, func(t *testing.T) {
				var buf bytes.Buffer
				if err := Write(&buf, format, tc.meta, tc.comps); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join("testdata", tc.file+ext)
				if *update {
					if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf.Bytes(), want) {
					t.Errorf("output differs from %s; run with -update and review the diff", path)
				}
			})
		}
	}
}
