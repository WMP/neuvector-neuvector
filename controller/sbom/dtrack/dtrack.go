// Package dtrack uploads SBOMs of running containers to Dependency-Track.
package dtrack

import (
	"time"

	"github.com/neuvector/neuvector/share"
)

const (
	DefaultProjectName    = "{cluster}/{rancher.project}/{namespace}/{replicaset}/{container}"
	DefaultProjectVersion = "{digest}"
	DefaultInactiveGrace  = 24 * 60 // minutes
)

// Vars holds the data of one container for the project templates.
type Vars struct {
	Cluster    string
	Namespace  string
	ReplicaSet string // pod owner name (any owner kind); "" for a pod without owner
	Service    string
	Pod        string
	Container  string
	Image      string
	Digest     string
	PodLabels  map[string]string
	NsLabels   map[string]string
}

// Project is a rendered Dependency-Track project.
type Project struct {
	Name    string
	Version string
	Tags    []string
	Parents []string // names of the parent projects from the root, e.g. "c1", "c1/ns"; the parents have no version
}

// Key is the deduplication key: project name and version.
func (p Project) Key() string { return p.Name + "\x00" + p.Version }

// WithDefaults returns cfg with empty templates and a zero grace period set to the defaults.
func WithDefaults(cfg share.CLUSDependencyTrack) share.CLUSDependencyTrack {
	if cfg.ProjectName == "" {
		cfg.ProjectName = DefaultProjectName
	}
	if cfg.ProjectVersion == "" {
		cfg.ProjectVersion = DefaultProjectVersion
	}
	if cfg.InactiveGrace == 0 {
		cfg.InactiveGrace = DefaultInactiveGrace
	}
	return cfg
}

// Grace returns the inactive grace period of cfg (after WithDefaults).
func Grace(cfg share.CLUSDependencyTrack) time.Duration {
	return time.Duration(cfg.InactiveGrace) * time.Minute
}
