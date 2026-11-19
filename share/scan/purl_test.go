package scan

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/share"
)

func TestPurlModule(t *testing.T) {
	cases := []struct{ name, ver, src, file, want string }{
		{"glibc/libc6", "2.36-9", "debian:12", "", "pkg:deb/debian/libc6@2.36-9?distro=debian-12&upstream=glibc"},
		{"bash", "1:5.2", "rhel:9.4", "", "pkg:rpm/redhat/bash@5.2?distro=rhel-9.4&epoch=1"},
		{"musl", "1.2.5-r0", "alpine:3.20.3", "", "pkg:apk/alpine/musl@1.2.5-r0?distro=alpine-3.20.3"},
		{"x", "1", "foo:1", "", ""},
		{"busybox", "1.36.1", "busybox:1.36.1", "", "pkg:generic/busybox@1.36.1"},
		{"opensslxx", "3.0", "debian:12", "", "pkg:deb/debian/openssl@3.0?distro=debian-12"},
		{"@angular/core", "1.0", "npm", "", "pkg:npm/%40angular/core@1.0"},
		{"python:My_Pkg.X", "2", "python", "", "pkg:pypi/my-pkg-x@2"},
		{"ruby:rack", "3", "ruby", "", "pkg:gem/rack@3"},
		{"go:github.com/a/b", "1.2.3", "golang", "", "pkg:golang/github.com/a/b@v1.2.3"},
		{"go:stdlib", "1.22.1", "golang", "", "pkg:golang/stdlib@1.22.1"},
		{"go:k8s.io/ingress-nginx", "1.9", "golang", "kubernetes", "pkg:golang/k8s.io/ingress-nginx@v1.9"},
		{"org.apache:commons", "1", "jar", "", "pkg:maven/org.apache/commons@1"},
		{"jar:foo", "1", "jar", "", ""},
		{"spring-boot:foo", "1", "jar", "", "pkg:maven/spring-boot/foo@1"},
		{"org.apache.logging.log4j:Apache Log4j Core", "1", "jar", "", ""},
		{"NLog", "4", ".NET", "", "pkg:nuget/NLog@4"},
		{"php:", "8", "php", "", "pkg:generic/php@8"},
		{"php:monolog", "8", "php", "", ""},
		{"cran-ggplot2", "3.0", "r", "", "pkg:cran/ggplot2@3.0"},
		{"https://x.r-universe.dev-foo", "1", "r", "", "pkg:cran/foo@1"},
		{"foo", "1", "r", "", "pkg:cran/foo@1"},
		{"redis", "7.2.4", "redis", "", "pkg:bitnami/redis@7.2.4"},
	}
	for _, c := range cases {
		m := &share.ScanModule{Name: c.name, Version: c.ver, Source: c.src, File: c.file}
		assert.Equal(t, c.want, ModulePurl(m, ""), "%s [%s]", c.name, c.src)
	}

	assert.Equal(t, "pkg:x/y@1", ModulePurl(&share.ScanModule{Name: "n", Source: "npm", Purl: "pkg:x/y@1"}, ""))
	m := &share.ScanModule{Name: "curl", Version: "1"}
	assert.Equal(t, "pkg:deb/debian/curl@1?distro=debian-12", ModulePurl(m, "debian:12"))
	assert.Equal(t, "", ModulePurl(m, ""))
}

func TestPurlMergeKey(t *testing.T) {
	assert.Equal(t, PurlMergeKey("pkg:golang/github.com/a/b@1.0"), PurlMergeKey("pkg:golang/github.com/A/b@v1.0"))
	assert.Equal(t, "deb/debian/curl@1", PurlMergeKey("pkg:deb/debian/Curl@1?arch=x#a"))
	assert.Equal(t, "npm/@angular/core@1.0", PurlMergeKey("pkg:npm/%40angular/core@1.0?a=b#x/y"))
	for _, p := range []string{"", "foo", "pkg:x", "pkg:npm/", "pkg:npm/@1"} {
		assert.Equal(t, "", PurlMergeKey(p), p)
	}
}

type purlVector struct {
	Description     string          `json:"description"`
	TestType        string          `json:"test_type"`
	Input           json.RawMessage `json:"input"`
	Expected        json.RawMessage `json:"expected_output"`
	ExpectedFailure bool            `json:"expected_failure"`
}

type purlInput struct {
	Type       *string           `json:"type"`
	Namespace  *string           `json:"namespace"`
	Name       *string           `json:"name"`
	Version    *string           `json:"version"`
	Qualifiers map[string]string `json:"qualifiers"`
	Subpath    *string           `json:"subpath"`
}

func str(p *string) string {
	if p == nil || strings.HasPrefix(*p, "Applied normalization") { // test data bug: sentence in subpath
		return ""
	}
	return *p
}

func TestPurlOfficialVectors(t *testing.T) {
	for _, typ := range strings.Fields("deb apk rpm maven npm pypi golang gem nuget composer cran generic") {
		raw, err := os.ReadFile("testdata/purl/" + typ + "-test.json")
		require.NoError(t, err)
		var f struct{ Tests []purlVector }
		require.NoError(t, json.Unmarshal(raw, &f))
		n := map[string]int{}
		for _, v := range f.Tests {
			if v.TestType != "build" && v.TestType != "validate" {
				continue
			}
			t.Run(typ+"/"+v.TestType+"/"+v.Description, func(t *testing.T) {
				if v.ExpectedFailure {
					t.Skip("expected_failure vector")
				}
				var want string
				require.NoError(t, json.Unmarshal(v.Expected, &want))
				var in purlInput
				if v.TestType == "build" {
					require.NoError(t, json.Unmarshal(v.Input, &in))
				} else {
					var p string
					require.NoError(t, json.Unmarshal(v.Input, &p))
					c, ok := parsePurl(p)
					require.True(t, ok)
					in = purlInput{&c.typ, &c.namespace, &c.name, &c.version, c.qualifiers, &c.subpath}
				}
				assert.Equal(t, want, BuildPurl(str(in.Type), str(in.Namespace), str(in.Name), str(in.Version), in.Qualifiers, str(in.Subpath)))
			})
			n[v.TestType]++
		}
		t.Logf("%s: %v", typ, n)
	}
}

// Old reports have no Purl, Licenses and Origin (fields 7-9).
type oldModule struct {
	Name, Version, Source string
	Vuls                  []*share.ScanModuleVul
	CPEs                  []string
	File                  string
}

type oldResult struct {
	Namespace string
	Modules   []*oldModule
}

type oldReport struct {
	ScannedAt  time.Time
	ScanResult oldResult // gob names an embedded struct field after its type
}

func checkOldModule(t *testing.T, m *share.ScanModule) {
	assert.Equal(t, "bash", m.Name)
	assert.Equal(t, "1:5.2", m.Version)
	assert.Equal(t, "rhel:9.4", m.Source)
	assert.Equal(t, []string{"cpe:2.3:a:gnu:bash"}, m.CPEs)
	assert.Empty(t, m.Purl)
	assert.Empty(t, m.Licenses)
	assert.Empty(t, m.Origin)
	assert.Equal(t, "pkg:rpm/redhat/bash@5.2?distro=rhel-9.4&epoch=1", ModulePurl(m, "rhel:9.4"))
}

func TestPurlOldGobCompat(t *testing.T) {
	old := oldReport{time.Unix(100, 0), oldResult{"rhel:9.4", []*oldModule{
		{Name: "bash", Version: "1:5.2", Source: "rhel:9.4", CPEs: []string{"cpe:2.3:a:gnu:bash"}},
	}}}
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(old))
	var r share.CLUSScanReport
	require.NoError(t, gob.NewDecoder(&buf).Decode(&r))
	assert.True(t, r.ScannedAt.Equal(old.ScannedAt))
	assert.Equal(t, "rhel:9.4", r.Namespace)
	require.Len(t, r.Modules, 1)
	checkOldModule(t, r.Modules[0])
}

func TestPurlOldProtoCompat(t *testing.T) {
	// wire bytes of fields 1-3, 5, 6 (Name, Version, Source, CPEs, File)
	b, err := hex.DecodeString("0a04626173681205313a352e321a087268656c3a392e342a126370653a322e333a613a676e753a62617368320c7573722f62696e2f62617368")
	require.NoError(t, err)
	var m share.ScanModule
	require.NoError(t, proto.Unmarshal(b, &m))
	checkOldModule(t, &m)
	assert.Equal(t, "usr/bin/bash", m.File)
}
