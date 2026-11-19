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
		{"Classpath-exception-2.0", licenseText, "Classpath-exception-2.0"},
		{"MIT WITH Apache-2.0", licenseText, "MIT WITH Apache-2.0"},
		{"Classpath-exception-2.0 WITH MIT", licenseText, "Classpath-exception-2.0 WITH MIT"},
		{"MIT WITH Classpath-exception-2.0+", licenseText, "MIT WITH Classpath-exception-2.0+"},
		{"(MIT) WITH Classpath-exception-2.0", licenseText, "(MIT) WITH Classpath-exception-2.0"},
		{"LicenseRef-x+", licenseText, "LicenseRef-x+"},
		{"GPL-2.0-or-later WITH classpath-exception-2.0", licenseExpr, "GPL-2.0-or-later WITH Classpath-exception-2.0"},
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

func TestSPDXIDSplit(t *testing.T) {
	for _, id := range []string{"mit", "gpl-2.0-with-classpath-exception"} {
		if _, ok := spdxLicenses[id]; !ok {
			t.Errorf("%q must be a license ID", id)
		}
	}
	for _, id := range []string{"classpath-exception-2.0", "llvm-exception"} {
		if _, ok := spdxExceptions[id]; !ok {
			t.Errorf("%q must be an exception ID", id)
		}
	}
	if n := len(spdxLicenses); n <= 600 {
		t.Errorf("split index %d, want > 600", n)
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
	pom := mod("jar", "com.fasterxml.jackson.core:jackson-core", "2.15.2")
	manifest := mod("jar", "jar:jackson-core", "2.15.2", "Apache-2.0") // same jar, MANIFEST.MF module
	pom.Purl = "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.15.2"
	manifest.Purl = pom.Purl

	runtimeModules := []*share.ScanModule{
		mod(deb, "bash", "5.2.15-2", "GPL-3.0-or-later"),
		mod(deb, "openssl", "3.0.11-1", "Apache-2.0 AND OpenSSL"),
		mod(deb, "nginx", "1.22.1", "bsd-2-clause"),
		nginxApp,
		mod("npm", "lodash", "4.17.21", "MIT"),
		mod("python", "python:requests", "2.31.0", "Apache-2.0 OR MIT", "GPL v2", "GPL-v2", "BSD", "LicenseRef-Vendor.1"),
		mod("python", "python:requests", "2.31.0"),
		syft,
		manifest,
		pom,
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

func TestDuplicateKeepsPurl(t *testing.T) {
	first := mod("jar", "Foo Bar", "1") // MANIFEST text: no purl
	second := mod("jar", "Foo Bar", "1")
	second.Purl = "pkg:maven/org.example/foo@1"
	if got := Components([]*share.ScanModule{first, second}, "", nil); len(got) != 1 || got[0].Purl != second.Purl {
		t.Errorf("got %+v", got)
	}
}

func TestCDXLicensesExpression(t *testing.T) {
	got := cdxLicenses([]string{"MIT", "apache-2.0 or gpl-2.0-only"})
	if got == nil || len(*got) != 1 || (*got)[0].Expression != "MIT AND (Apache-2.0 OR GPL-2.0-only)" {
		t.Errorf("expression with another license: %+v", got)
	}
	// free text cannot be part of an expression: separate license entries
	if got := cdxLicenses([]string{"GPL v2", "MIT OR Apache-2.0"}); got == nil || len(*got) != 2 || (*got)[1].License == nil || (*got)[1].License.Name != "MIT OR Apache-2.0" {
		t.Errorf("with free text: %+v", got)
	}
	if got := cdxLicenses([]string{"MIT", "Apache-2.0"}); got == nil || len(*got) != 2 || (*got)[0].License.ID != "MIT" {
		t.Errorf("only IDs: %+v", got)
	}
}

func TestMergeByPurl(t *testing.T) {
	const log4j = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	withPurl := func(m *share.ScanModule, purl string) *share.ScanModule { m.Purl = purl; return m }
	manifest := func() *share.ScanModule {
		return withPurl(mod("jar", "jar:log4j-core", "2.14.1", "Apache-2.0"), log4j) // scanner: "vendor:title"
	}
	pom := func() *share.ScanModule {
		return withPurl(mod("jar", "org.apache.logging.log4j:log4j-core", "2.14.1"), log4j)
	}

	// pom.properties and MANIFEST.MF of one jar, in both orders: one component with the pom name
	for _, mods := range [][]*share.ScanModule{{manifest(), pom()}, {pom(), manifest()}} {
		got := Components(mods, "", nil)
		if len(got) != 1 || got[0].Name != "org.apache.logging.log4j:log4j-core" || got[0].Purl != log4j ||
			len(got[0].Licenses) != 1 || got[0].Licenses[0] != "Apache-2.0" {
			t.Errorf("pom + MANIFEST: %+v", got)
		}
	}

	// one npm package in 2 directories (purl derived from Source/Name/Version, File differs)
	a, b := mod("npm", "lodash", "4.17.21", "MIT"), mod("npm", "lodash", "4.17.21")
	a.File, b.File = "/app/node_modules/lodash", "/usr/lib/node_modules/lodash"
	if got := Components([]*share.ScanModule{a, b}, "", nil); len(got) != 1 || got[0].Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("npm in 2 directories: %+v", got)
	}

	// runtime only when no merged module is in the image; the image module matches by purl
	img := []*share.ScanModule{withPurl(mod("jar", "x", "1", "MIT"), log4j)}
	if got := Components([]*share.ScanModule{manifest(), pom()}, "", img); len(got) != 1 || got[0].Runtime ||
		strings.Join(got[0].Licenses, ",") != "Apache-2.0,MIT" {
		t.Errorf("in image by purl: %+v", got)
	}
	if got := Components([]*share.ScanModule{manifest(), pom()}, "", []*share.ScanModule{}); len(got) != 1 || !got[0].Runtime {
		t.Errorf("not in image: %+v", got)
	}

	// different purls (rpm epoch qualifier) stay separate even with the same NeuVector name
	r1, r2 := mod("centos:7", "bash", "4.2"), mod("centos:7", "bash", "4.2")
	r1.Purl, r2.Purl = "pkg:rpm/centos/bash@4.2?epoch=1", "pkg:rpm/centos/bash@4.2?epoch=2"
	if got := Components([]*share.ScanModule{r1, r2}, "", nil); len(got) != 2 {
		t.Errorf("different purls: %+v", got)
	}

	// a scanner purl with more qualifiers and a derived purl of the same key: one component
	d1, d2 := mod("debian:12", "bash", "5.2"), mod("debian:12", "bash", "5.2")
	d1.Purl = "pkg:deb/debian/bash@5.2?arch=amd64&distro=debian-12"
	if got := Components([]*share.ScanModule{d1, d2}, "", nil); len(got) != 1 {
		t.Errorf("scanner and derived purl: %+v", got)
	}

	// generic purls come from the Source only: different modules stay separate
	o1, o2 := mod("openshift", "openshift.kubernetes", "4.14"), mod("openshift", "openshift", "4.14")
	if got := Components([]*share.ScanModule{o1, o2}, "", nil); len(got) != 2 {
		t.Errorf("generic purls: %+v", got)
	}

	// image match by the normalized key (golang "v" prefix)
	g := mod("golang", "go:github.com/a/b", "1.0")
	gImg := withPurl(mod("golang", "go:github.com/a/b", "v1.0", "MIT"), "pkg:golang/github.com/a/b@v1.0")
	if got := Components([]*share.ScanModule{g}, "", []*share.ScanModule{gImg}); len(got) != 1 || got[0].Runtime || len(got[0].Licenses) != 1 {
		t.Errorf("image match by key: %+v", got)
	}

	// same purl, different version strings: the smaller one, whatever the order
	s1, s2 := mod("golang", "go:stdlib", "1.22.1 X:boringcrypto"), mod("golang", "go:stdlib", "1.22.1")
	for _, mods := range [][]*share.ScanModule{{s1, s2}, {s2, s1}} {
		if got := Components(mods, "", nil); len(got) != 1 || got[0].Version != "1.22.1" {
			t.Errorf("stdlib versions: %+v", got)
		}
	}

	// a module without purl joins the first component of its key
	j1, j2, j3 := mod("jar", "Foo Bar", "1"), mod("jar", "Foo Bar", "1"), mod("jar", "Foo Bar", "1", "MIT")
	j1.Purl, j2.Purl = "pkg:maven/a/foo@1", "pkg:maven/b/foo@1"
	got := Components([]*share.ScanModule{j1, j2, j3}, "", nil)
	if len(got) != 2 {
		t.Fatalf("no-purl module: %+v", got)
	}
	for _, c := range got {
		if (c.Purl == j1.Purl) != (len(c.Licenses) == 1) {
			t.Errorf("no-purl module must join the first component: %+v", got)
		}
	}
}
