package rest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/sbom/dtrack"
	"github.com/neuvector/neuvector/share"
)

const maxDTrackGrace = 525600 // minutes, one year

// The API key is never logged or returned. Do not pass the request struct to a logger or audit call.

func handlerDependencyTrackGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	// the setting is global; the sbom permission is the gate (no system config permission needed)
	if !acc.HasGlobalPermissions(share.PERM_SBOM, 0) {
		restRespAccessDenied(w, login)
		return
	}

	cconf, _ := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl())
	if cconf == nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
		return
	}
	cfg := dtrack.WithDefaults(cconf.DependencyTrack)
	resp := &api.RESTDependencyTrackData{Config: &api.RESTDependencyTrack{
		Enabled:        cfg.Enabled,
		URL:            cfg.URL,
		APIKeySet:      cfg.APIKey != "",
		ProjectName:    cfg.ProjectName,
		ProjectVersion: cfg.ProjectVersion,
		Tags:           append([]string{}, cfg.Tags...),
		InactiveGrace:  cfg.InactiveGrace,
	}}
	restRespSuccess(w, r, resp, acc, login, nil, "")
}

func validateDTrackURL(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("Invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("URL scheme must be http or https")
	}
	if u.Hostname() == "" {
		return "", errors.New("URL has no host")
	}
	if u.User != nil {
		return "", errors.New("URL must not contain credentials; use api_key")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("URL must not contain a query or fragment")
	}
	return strings.TrimRight(raw, "/"), nil
}

func hasControlChar(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

func handlerDependencyTrackConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	if !acc.HasGlobalPermissions(share.PERM_SBOM, share.PERM_SBOM) {
		restRespAccessDenied(w, login)
		return
	}

	body, err := io.ReadAll(getDefaultReader(r.Body))
	if err != nil {
		log.WithError(err).Warn("failed to read request body")
	}
	var rconf api.RESTDependencyTrackConfigData
	if err = json.Unmarshal(body, &rconf); err != nil || rconf.Config == nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	req := rconf.Config

	bad := func(msg string) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
	}
	newURL := ""
	if req.URL != nil {
		if newURL, err = validateDTrackURL(*req.URL); err != nil {
			bad(err.Error())
			return
		}
	}
	var newKey string
	if req.APIKey != nil {
		newKey = strings.TrimSpace(*req.APIKey)
		if hasControlChar(newKey) {
			bad("API key contains a control character")
			return
		}
	}
	if req.InactiveGrace != nil && *req.InactiveGrace > maxDTrackGrace {
		bad("inactive_grace_period is too large")
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	retry := 0
	for retry < retryClusterMax {
		cconf, rev := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl())
		if cconf == nil {
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
			return
		}

		cfg := cconf.DependencyTrack
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.URL != nil {
			// the stored key must not follow the URL to another server
			if newURL != cfg.URL && req.APIKey == nil && cfg.APIKey != "" {
				bad("api_key is required when the URL changes")
				return
			}
			cfg.URL = newURL
		}
		if req.APIKey != nil {
			cfg.APIKey = newKey
		}
		if req.ProjectName != nil {
			cfg.ProjectName = *req.ProjectName
		}
		if req.ProjectVersion != nil {
			cfg.ProjectVersion = *req.ProjectVersion
		}
		if req.Tags != nil {
			cfg.Tags = *req.Tags
		}
		if req.InactiveGrace != nil {
			cfg.InactiveGrace = *req.InactiveGrace
		}
		if cfg.Enabled && (cfg.URL == "" || cfg.APIKey == "") {
			bad("URL and API key are required to enable Dependency-Track")
			return
		}
		if err := dtrack.ValidateTemplates(cfg.ProjectName, cfg.ProjectVersion, cfg.Tags); err != nil {
			bad(err.Error())
			return
		}

		cconf.DependencyTrack = cfg
		if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("Failed to write Dependency-Track config")
			retry++
		} else {
			break
		}
	}
	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Configure Dependency-Track")
}

// handlerDependencyTrackPreview renders the project of a workload; it uploads nothing and needs no API key.
func handlerDependencyTrackPreview(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}
	// write, like the configuration: sbom read alone must not show pod and namespace labels
	if !acc.HasGlobalPermissions(share.PERM_SBOM, share.PERM_SBOM) {
		restRespAccessDenied(w, login)
		return
	}

	body, err := io.ReadAll(getDefaultReader(r.Body))
	var req api.RESTDependencyTrackPreviewReq
	if err != nil || json.Unmarshal(body, &req) != nil || req.WorkloadID == "" {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	cconf, _ := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl())
	if cconf == nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
		return
	}
	cfg := cconf.DependencyTrack // omitted templates keep the stored value
	if req.ProjectName != nil {
		cfg.ProjectName = *req.ProjectName
	}
	if req.ProjectVersion != nil {
		cfg.ProjectVersion = *req.ProjectVersion
	}
	if req.Tags != nil {
		cfg.Tags = *req.Tags
	}
	if err := dtrack.ValidateTemplates(cfg.ProjectName, cfg.ProjectVersion, cfg.Tags); err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if _, err := cacher.GetWorkload(req.WorkloadID, "", acc); err != nil {
		sbomRespErr(w, login, err)
		return
	}
	resp := &api.RESTDependencyTrackPreview{Tags: []string{}, Parents: []string{}}
	proj, err := cacher.DtrackPreview(req.WorkloadID, cfg)
	switch {
	case err == nil:
		resp.ProjectName, resp.ProjectVersion = proj.Name, proj.Version
		resp.Parents = append(resp.Parents, proj.Parents...)
		resp.Tags = append(resp.Tags, proj.Tags...)
	case errors.Is(err, cache.ErrDtrackPodUnknown), errors.Is(err, cache.ErrDtrackNotRunning), errors.Is(err, cache.ErrDtrackNotScanned), errors.Is(err, dtrack.ErrEmptySymbol):
		resp.SkippedReason = err.Error()
	default:
		log.WithFields(log.Fields{"error": err}).Error("Failed to render the Dependency-Track project")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
		return
	}
	restRespSuccess(w, r, resp, acc, login, nil, "")
}
