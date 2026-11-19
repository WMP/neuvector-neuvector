package sbom

import (
	"fmt"
	"strings"

	goversion "github.com/hashicorp/go-version"

	"github.com/neuvector/neuvector/share/utils"
)

// Version comparison per purl type:
//   - deb, rpm, apk, alpm and "" (no purl, an OS package): utils.NewVersion (dpkg algorithm, as admission control).
//   - every other type (maven, npm, pypi, golang, gem, ...): go-version (semver); when it cannot parse a side, utils.NewVersion.
//   - when no comparator parses a side: "=" matches on equal strings, the other operators never match.

const maxVersionConstraints = 8

type constraint struct {
	op, version string
}

// VersionQuery is a parsed version filter: all constraints must hold.
type VersionQuery []constraint

// ops are ordered so that a two-character operator is tried before its one-character prefix.
var ops = []string{"<=", ">=", "==", "=", "<", ">"}

// ParseVersionQuery parses "1.2", "=1.2", "<2.0" or ">=1.0, <2.0".
func ParseVersionQuery(s string) (VersionQuery, error) {
	parts := strings.Split(s, ",")
	if len(parts) > maxVersionConstraints {
		return nil, fmt.Errorf("more than %d version constraints", maxVersionConstraints)
	}
	q := make(VersionQuery, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		op := "="
		for _, o := range ops {
			if strings.HasPrefix(p, o) {
				op, p = o, strings.TrimSpace(p[len(o):])
				break
			}
		}
		if p == "" {
			return nil, fmt.Errorf("empty version constraint")
		}
		if c := p[0] | 0x20; (c < '0' || c > '9') && (c < 'a' || c > 'z') { // an unknown operator such as "~"
			return nil, fmt.Errorf("invalid version %q", p)
		}
		if _, ok := compare("maven", p, p); !ok {
			return nil, fmt.Errorf("invalid version %q", p)
		}
		if op == "==" {
			op = "="
		}
		q = append(q, constraint{op, p})
	}
	return q, nil
}

// Match reports whether version satisfies all constraints. purlType is the type of the component purl, "" when it has none.
func (q VersionQuery) Match(purlType, version string) bool {
	for _, c := range q {
		cmp, ok := compare(purlType, version, c.version)
		if !ok {
			if c.op != "=" || version != c.version {
				return false
			}
			continue
		}
		if !holds(c.op, cmp) {
			return false
		}
	}
	return true
}

func holds(op string, cmp int) bool {
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	}
	return cmp == 0
}

func compare(purlType, a, b string) (int, bool) {
	switch purlType {
	case "deb", "rpm", "apk", "alpm", "":
	default:
		va, ea := goversion.NewVersion(a)
		vb, eb := goversion.NewVersion(b)
		if ea == nil && eb == nil {
			return va.Compare(vb), true
		}
	}
	ua, ea := utils.NewVersion(a)
	ub, eb := utils.NewVersion(b)
	if ea != nil || eb != nil {
		return 0, false
	}
	return ua.Compare(ub), true
}
