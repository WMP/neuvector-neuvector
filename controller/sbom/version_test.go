package sbom

import "testing"

func TestVersionMatch(t *testing.T) {
	cases := []struct {
		query, typ, ver string
		want            bool
	}{
		{"2.17.1", "maven", "2.17.1", true},
		{"=2.17.1", "maven", "2.17.0", false},
		{"==2.17.1", "maven", "2.17.1", true},
		{"<2.17.1", "maven", "2.17.0", true},
		{"<2.17.1", "maven", "2.17.1", false},
		{"<=2.17.1", "maven", "2.17.1", true},
		{">2.17.1", "maven", "2.17.2", true},
		{">2.17.1", "maven", "2.17.1", false},
		{">=2.17.1", "maven", "2.17.1", true},
		{">=1.0, <2.0", "npm", "1.5.0", true},
		{">=1.0, <2.0", "npm", "2.0.0", false},
		{">=1.0, <2.0", "npm", "0.9", false},
		{"<2.0.0", "maven", "2.0.0-beta1", true},
		{">1:1.0-1", "deb", "2.0", false},
		{"<1:1.0-1", "deb", "2.0", true},
		{">2.0", "deb", "1:1.0-1", true},
		{">1.0-1", "", "1.0-2", true},
		{">=1.2.3", "golang", "v1.2.4", true},
		{"<v1.2.3", "golang", "1.2.2", true},
		{"=1.0", "generic", "not a version!", false},
		{"=zzz", "generic", "zzz", true},
		{"<2.0", "generic", "not a version!", false},
	}
	for _, c := range cases {
		q, err := ParseVersionQuery(c.query)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.query, err)
			continue
		}
		if got := q.Match(c.typ, c.ver); got != c.want {
			t.Errorf("%q %s %q: got %v, want %v", c.query, c.typ, c.ver, got, c.want)
		}
	}
}

func TestParseVersionQueryError(t *testing.T) {
	for _, s := range []string{"", "<", ">=1.0,", "~1.0", "1,2,3,4,5,6,7,8,9", "=!!!"} {
		if _, err := ParseVersionQuery(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}
