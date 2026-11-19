package dtrack

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/neuvector/neuvector/share"
)

const (
	maxTemplateLen = 1024
	maxTags        = 50

	podLabelPrefix = "pod.metadata.labels."
	nsLabelPrefix  = "namespace.metadata.labels."
)

// ErrEmptySymbol is returned when a symbol used in the project name or version has no value.
var ErrEmptySymbol = errors.New("empty template symbol")

var fixedSymbols = map[string]func(Vars) string{
	"cluster":    func(v Vars) string { return v.Cluster },
	"namespace":  func(v Vars) string { return v.Namespace },
	"replicaset": func(v Vars) string { return v.ReplicaSet },
	"service":    func(v Vars) string { return v.Service },
	"pod":        func(v Vars) string { return v.Pod },
	"container":  func(v Vars) string { return v.Container },
	"image":      func(v Vars) string { return v.Image },
	"digest":     func(v Vars) string { return v.Digest },
}

func validLabelKey(k string) bool {
	if k == "" {
		return false
	}
	for _, c := range k {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._/-", c)
		if !ok {
			return false
		}
	}
	return true
}

func knownSymbol(s string) bool {
	if _, ok := fixedSymbols[s]; ok {
		return true
	}
	for _, p := range []string{podLabelPrefix, nsLabelPrefix} {
		if strings.HasPrefix(s, p) {
			return validLabelKey(s[len(p):])
		}
	}
	return false
}

// parseSymbols returns the symbols (without braces) of a template and checks the template syntax.
func parseSymbols(tpl string) ([]string, error) {
	if len(tpl) > maxTemplateLen {
		return nil, fmt.Errorf("longer than %d characters", maxTemplateLen)
	}
	var syms []string
	start := -1
	for i, c := range tpl {
		switch {
		case unicode.IsControl(c):
			return nil, errors.New("contains a control character")
		case c == '{':
			if start >= 0 {
				return nil, fmt.Errorf("nested brace in %q", tpl[start:i+1])
			}
			start = i
		case c == '}':
			if start < 0 {
				return nil, fmt.Errorf("unbalanced brace at position %d", i)
			}
			s := tpl[start+1 : i]
			if !knownSymbol(s) {
				return nil, fmt.Errorf("unknown symbol %q", tpl[start:i+1])
			}
			syms = append(syms, s)
			start = -1
		}
	}
	if start >= 0 {
		return nil, fmt.Errorf("unbalanced brace in %q", tpl[start:])
	}
	return syms, nil
}

func symbolValue(s string, v Vars) string {
	if f, ok := fixedSymbols[s]; ok {
		return f(v)
	}
	if strings.HasPrefix(s, podLabelPrefix) {
		return v.PodLabels[s[len(podLabelPrefix):]]
	}
	return v.NsLabels[s[len(nsLabelPrefix):]]
}

// ValidateTemplates checks the project name, version and tag templates. Empty name and version mean the defaults.
func ValidateTemplates(name, version string, tags []string) error {
	for _, t := range []struct{ field, tpl string }{{"project name", name}, {"project version", version}} {
		if _, err := parseSymbols(t.tpl); err != nil {
			return fmt.Errorf("%s in %s", err, t.field)
		}
	}
	if len(tags) > maxTags {
		return fmt.Errorf("more than %d tags", maxTags)
	}
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			return errors.New("empty tag")
		}
		if strings.Contains(tag, ",") {
			return fmt.Errorf("tag %q contains a comma", tag)
		}
		if _, err := parseSymbols(tag); err != nil {
			return fmt.Errorf("%s in tag %q", err, tag)
		}
	}
	return nil
}

// expand renders one template in a single pass: values are never expanded again.
// It returns the first used symbol that has no value, "" if there is none.
func expand(tpl string, v Vars) (out, emptySym string, err error) {
	syms, err := parseSymbols(tpl)
	if err != nil {
		return "", "", err
	}
	var oldnew []string
	for name, f := range fixedSymbols {
		oldnew = append(oldnew, "{"+name+"}", f(v))
	}
	seen := map[string]bool{}
	for _, s := range syms {
		if symbolValue(s, v) == "" && emptySym == "" {
			emptySym = s
		}
		if _, fixed := fixedSymbols[s]; !fixed && !seen[s] {
			seen[s] = true
			oldnew = append(oldnew, "{"+s+"}", symbolValue(s, v))
		}
	}
	return strings.TrimSpace(strings.NewReplacer(oldnew...).Replace(tpl)), emptySym, nil
}

// Render builds the project of a container from the templates of cfg (defaults applied).
func Render(cfg share.CLUSDependencyTrack, v Vars) (Project, error) {
	cfg = WithDefaults(cfg)
	var p Project

	// a pod without owner has no ReplicaSet: use the pod name so that pods do not share a project
	nv := v
	if nv.ReplicaSet == "" {
		nv.ReplicaSet = v.Pod
	}
	for _, f := range []struct {
		field, tpl string
		out        *string
	}{{"project name", cfg.ProjectName, &p.Name}, {"project version", cfg.ProjectVersion, &p.Version}} {
		s, empty, err := expand(f.tpl, nv)
		if err != nil {
			return Project{}, fmt.Errorf("%s: %w", f.field, err)
		}
		if empty != "" {
			return Project{}, fmt.Errorf("%w: {%s} in %s", ErrEmptySymbol, empty, f.field)
		}
		if s == "" {
			return Project{}, fmt.Errorf("%w: %s is empty", ErrEmptySymbol, f.field)
		}
		*f.out = s
	}

	seen := map[string]bool{}
	for _, t := range cfg.Tags {
		s, empty, err := expand(t, v)
		if err != nil || empty != "" || s == "" || strings.Contains(s, ",") || seen[s] {
			continue
		}
		seen[s] = true
		p.Tags = append(p.Tags, s)
	}
	return p, nil
}
