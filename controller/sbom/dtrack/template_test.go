package dtrack

import (
	"errors"
	"testing"

	"github.com/neuvector/neuvector/share"
)

var testVars = Vars{
	Cluster: "c1", Namespace: "ns", ReplicaSet: "rs", Service: "svc", Pod: "pod-1",
	Container: "ctr", Image: "img:1", Digest: "sha256:abc",
	PodLabels: map[string]string{"app": "web", "a.b/c-d": "x"},
	NsLabels:  map[string]string{"team": "core"},
}

func TestRenderSymbols(t *testing.T) {
	tests := []struct{ tpl, want string }{
		{"{cluster}", "c1"}, {"{namespace}", "ns"}, {"{replicaset}", "rs"}, {"{service}", "svc"},
		{"{pod}", "pod-1"}, {"{container}", "ctr"}, {"{image}", "img:1"}, {"{digest}", "sha256:abc"},
		{"{pod.metadata.labels.app}", "web"}, {"{pod.metadata.labels.a.b/c-d}", "x"},
		{"{namespace.metadata.labels.team}-{pod.metadata.labels.app}", "core-web"},
		{"  {cluster}  ", "c1"},
	}
	for _, tt := range tests {
		p, err := Render(share.CLUSDependencyTrack{ProjectName: tt.tpl}, testVars)
		if err != nil || p.Name != tt.want {
			t.Errorf("%q: got %q, %v; want %q", tt.tpl, p.Name, err, tt.want)
		}
	}
}

func TestRenderDefaults(t *testing.T) {
	p, err := Render(share.CLUSDependencyTrack{}, testVars)
	if err != nil || p.Name != "c1/ns/rs/ctr" || p.Version != "sha256:abc" || len(p.Tags) != 0 {
		t.Errorf("got %+v, %v", p, err)
	}
}

func TestRenderMissing(t *testing.T) {
	for _, cfg := range []share.CLUSDependencyTrack{
		{ProjectName: "{pod.metadata.labels.nope}"},
		{ProjectVersion: "{namespace.metadata.labels.nope}"},
		{ProjectName: "{service}"},
		{ProjectName: "  "},
	} {
		v := testVars
		if cfg.ProjectName == "{service}" {
			v.Service = ""
		}
		if _, err := Render(cfg, v); !errors.Is(err, ErrEmptySymbol) {
			t.Errorf("%+v: err=%v, want ErrEmptySymbol", cfg, err)
		}
	}
}

func TestRenderTags(t *testing.T) {
	cfg := share.CLUSDependencyTrack{Tags: []string{"a", "{pod.metadata.labels.nope}", " {cluster} ", "a", "", "{service}", "x,y"}}
	v := testVars
	v.Service = ""
	p, err := Render(cfg, v)
	if err != nil || len(p.Tags) != 2 || p.Tags[0] != "a" || p.Tags[1] != "c1" {
		t.Errorf("got %+v, %v", p.Tags, err)
	}
	v = testVars
	v.PodLabels = map[string]string{"app": "a,b"}
	p, _ = Render(share.CLUSDependencyTrack{Tags: []string{"{pod.metadata.labels.app}"}}, v)
	if len(p.Tags) != 0 {
		t.Errorf("tag with comma from value kept: %v", p.Tags)
	}
}

func TestRenderReplicaSetFallback(t *testing.T) {
	a, b := testVars, testVars
	a.ReplicaSet, a.Pod = "", "pod-a"
	b.ReplicaSet, b.Pod = "", "pod-b"
	pa, err1 := Render(share.CLUSDependencyTrack{}, a)
	pb, err2 := Render(share.CLUSDependencyTrack{}, b)
	if err1 != nil || err2 != nil || pa.Name == pb.Name || pa.Name != "c1/ns/pod-a/ctr" {
		t.Errorf("%q %q %v %v", pa.Name, pb.Name, err1, err2)
	}
	r1, r2 := testVars, testVars
	r1.Pod, r2.Pod = "pod-1", "pod-2"
	p1, _ := Render(share.CLUSDependencyTrack{}, r1)
	p2, _ := Render(share.CLUSDependencyTrack{}, r2)
	if p1.Key() != p2.Key() {
		t.Errorf("replicas of one ReplicaSet differ: %q %q", p1.Key(), p2.Key())
	}
}

func TestRenderNoReexpand(t *testing.T) {
	v := testVars
	v.Namespace = "{cluster}"
	v.PodLabels = map[string]string{"app": "{namespace}"}
	p, err := Render(share.CLUSDependencyTrack{ProjectName: "{namespace}/{pod.metadata.labels.app}"}, v)
	if err != nil || p.Name != "{cluster}/{namespace}" {
		t.Errorf("got %q, %v", p.Name, err)
	}
}

func TestValidateTemplates(t *testing.T) {
	long := make([]byte, 1025)
	for i := range long {
		long[i] = 'a'
	}
	many := make([]string, 51)
	for i := range many {
		many[i] = "t"
	}
	bad := []struct {
		name, ver string
		tags      []string
	}{
		{"{foo}", "", nil}, {"", "{foo}", nil}, {"{pod.metadata.labels.}", "", nil},
		{"{pod.metadata.labels.a b}", "", nil}, {"{cluster", "", nil}, {"cluster}", "", nil},
		{"{{cluster}}", "", nil}, {"a\nb", "", nil}, {string(long), "", nil},
		{"", "", []string{"a,b"}}, {"", "", []string{" "}}, {" ", "", nil}, {"", "  ", nil}, {"", "", []string{"{x}"}}, {"", "", many},
	}
	for _, b := range bad {
		if err := ValidateTemplates(b.name, b.ver, b.tags); err == nil {
			t.Errorf("%+v: no error", b)
		}
	}
	if err := ValidateTemplates("", "", nil); err != nil {
		t.Error(err)
	}
	if err := ValidateTemplates("{cluster}-{namespace.metadata.labels.a_b/c}", "v{digest}", []string{"{image}", "x"}); err != nil {
		t.Error(err)
	}
	if err := ValidateTemplates("{foo}", "", nil); err == nil || err.Error() != `unknown symbol "{foo}" in project name` {
		t.Errorf("message: %v", err)
	}
}
