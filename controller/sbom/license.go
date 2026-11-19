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

// spdxLicenses and spdxExceptions map lowercase SPDX IDs to their canonical case.
// The enum is the license IDs sorted case-insensitively, then the exception IDs
// sorted the same way, so the exceptions start where the order breaks.
var spdxLicenses, spdxExceptions = func() (map[string]string, map[string]string) {
	var s struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(spdxSchema, &s); err != nil {
		panic(err)
	}
	split := splitIndex(s.Enum)
	toMap := func(ids []string) map[string]string {
		m := make(map[string]string, len(ids))
		for _, id := range ids {
			m[strings.ToLower(id)] = id
		}
		return m
	}
	return toMap(s.Enum[:split]), toMap(s.Enum[split:])
}()

// splitIndex returns the first index whose ID sorts before its predecessor.
func splitIndex(enum []string) int {
	for k := 1; k < len(enum); k++ {
		if strings.ToLower(enum[k]) < strings.ToLower(enum[k-1]) {
			return k
		}
	}
	return len(enum)
}

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
	if id, ok := spdxLicenses[strings.ToLower(l)]; ok {
		return licenseID, id
	}
	if licenseRefRe.MatchString(l) {
		return licenseID, l
	}
	toks := strings.Fields(parenSplitter.Replace(l))
	wantOperand, afterWith, depth := true, false, 0
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
			if wantOperand || (up == "WITH" && toks[i-1] == ")") {
				return licenseText, l
			}
			wantOperand, afterWith = true, up == "WITH"
			t = up
		default:
			id, ok := expressionOperand(t, afterWith)
			if !wantOperand || !ok {
				return licenseText, l
			}
			wantOperand, afterWith = false, false
			t = id
		}
		if i > 0 && toks[i-1] != "(" && t != ")" {
			b.WriteByte(' ')
		}
		b.WriteString(t)
	}
	if wantOperand || depth != 0 {
		return licenseText, l
	}
	return licenseExpr, b.String()
}

// expressionOperand validates an expression operand and returns its canonical form.
// After WITH it must be an exception ID; otherwise a license ID, with an optional
// "+", or a LicenseRef.
func expressionOperand(t string, afterWith bool) (string, bool) {
	if afterWith {
		id, ok := spdxExceptions[strings.ToLower(t)]
		return id, ok
	}
	base, plus := strings.CutSuffix(t, "+")
	if id, ok := spdxLicenses[strings.ToLower(base)]; ok {
		if plus {
			id += "+"
		}
		return id, true
	}
	return t, !plus && licenseRefRe.MatchString(t)
}
