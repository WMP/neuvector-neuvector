package sbom

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

// spdx.schema.json is the SPDX license ID list from the CycloneDX 1.6 specification
// (github.com/CycloneDX/specification, tag 1.6, Apache-2.0).
//
//go:embed spdx.schema.json
var spdxSchema []byte

// spdxIDs maps lowercase SPDX license/exception IDs to their canonical case.
var spdxIDs = func() map[string]string {
	var s struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(spdxSchema, &s); err != nil {
		panic(err)
	}
	m := make(map[string]string, len(s.Enum))
	for _, id := range s.Enum {
		m[strings.ToLower(id)] = id
	}
	return m
}()

type licenseKind int

const (
	licenseText licenseKind = iota // free text
	licenseID                      // single SPDX or LicenseRef ID
	licenseExpr                    // SPDX expression
)

var (
	licenseRefRe   = regexp.MustCompile(`^LicenseRef-[A-Za-z0-9.-]+$`)
	licenseRefFind = regexp.MustCompile(`LicenseRef-[A-Za-z0-9.-]+`)
	parenSplitter  = strings.NewReplacer("(", " ( ", ")", " ) ")
)

// classifyLicense returns the kind of l and its normalized form: canonical case
// for IDs, uppercase operators for expressions, l (trimmed) for free text.
func classifyLicense(l string) (licenseKind, string) {
	l = strings.TrimSpace(l)
	if id, ok := spdxIDs[strings.ToLower(l)]; ok {
		return licenseID, id
	}
	if licenseRefRe.MatchString(l) {
		return licenseID, l
	}
	toks := strings.Fields(parenSplitter.Replace(l))
	wantOperand, depth := true, 0
	var b strings.Builder
	for i, t := range toks {
		switch up := strings.ToUpper(t); {
		case t == "(":
			if !wantOperand {
				return licenseText, l
			}
			depth++
		case t == ")":
			if wantOperand || depth == 0 {
				return licenseText, l
			}
			depth--
		case up == "AND" || up == "OR" || up == "WITH":
			if wantOperand {
				return licenseText, l
			}
			wantOperand = true
			t = up
		default:
			id, ok := expressionOperand(t)
			if !wantOperand || !ok {
				return licenseText, l
			}
			wantOperand = false
			t = id
		}
		if i > 0 && toks[i-1] != "(" && t != ")" {
			b.WriteByte(' ')
		}
		b.WriteString(t)
	}
	if wantOperand || depth != 0 || len(toks) < 2 {
		return licenseText, l
	}
	return licenseExpr, b.String()
}

// expressionOperand validates a license ID, optionally followed by "+", and returns its canonical form.
func expressionOperand(t string) (string, bool) {
	base, plus := strings.CutSuffix(t, "+")
	if id, ok := spdxIDs[strings.ToLower(base)]; ok {
		base = id
	} else if !licenseRefRe.MatchString(base) {
		return "", false
	}
	if plus {
		base += "+"
	}
	return base, true
}
