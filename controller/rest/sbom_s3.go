package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/share"
)

func handlerSBOMStorageGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	if !acc.HasGlobalPermissions(share.PERM_SBOM, 0) {
		restRespAccessDenied(w, login)
		return
	}

	cconf, _ := clusHelper.GetSystemConfigRev(access.NewAdminAccessControl())
	if cconf == nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
		return
	}
	c := cconf.SBOMStorage
	grace := c.DeleteGrace
	if grace == 0 {
		grace = s3store.DefaultGraceMinutes
	}
	resp := &api.RESTSBOMStorageData{Config: &api.RESTSBOMStorage{
		Enabled: c.Enabled, Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix,
		PathStyle: c.PathStyle, AccessKey: c.AccessKey, SecretKeySet: c.SecretKey != "",
		DeleteUnused: c.DeleteUnused, DeleteGrace: grace,
	}}
	restRespSuccess(w, r, resp, acc, login, nil, "Get SBOM storage configuration")
}

func handlerSBOMStorageConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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
	var rc api.RESTSBOMStorageConfigData
	if err == nil {
		err = json.Unmarshal(body, &rc)
	}
	if err != nil || rc.Config == nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	req := rc.Config

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

		cfg := cconf.SBOMStorage
		if req.Enabled != nil {
			cfg.Enabled = *req.Enabled
		}
		if req.Endpoint != nil {
			cfg.Endpoint = strings.TrimRight(strings.TrimSpace(*req.Endpoint), "/")
		}
		if req.Region != nil {
			cfg.Region = strings.TrimSpace(*req.Region)
		}
		if req.Bucket != nil {
			cfg.Bucket = strings.TrimSpace(*req.Bucket)
		}
		if req.Prefix != nil {
			cfg.Prefix = strings.TrimSpace(*req.Prefix)
		}
		if req.PathStyle != nil {
			cfg.PathStyle = *req.PathStyle
		}
		if req.AccessKey != nil {
			cfg.AccessKey = strings.TrimSpace(*req.AccessKey)
		}
		if req.SecretKey != nil {
			cfg.SecretKey = *req.SecretKey // not trimmed: Validate rejects surrounding spaces
		}
		if req.DeleteUnused != nil {
			cfg.DeleteUnused = *req.DeleteUnused
		}
		if req.DeleteGrace != nil {
			cfg.DeleteGrace = *req.DeleteGrace
		}

		// the stored secret must not follow the endpoint to another server
		if cfg.Endpoint != cconf.SBOMStorage.Endpoint && req.SecretKey == nil && cconf.SBOMStorage.SecretKey != "" {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "secret_key is required when the endpoint changes")
			return
		}
		if err := s3store.Validate(cfg); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		cconf.SBOMStorage = cfg
		if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}
	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Configure SBOM storage")
}

func handlerSBOMStorageImages(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	resp := &api.RESTSBOMStorageImagesData{Images: []*api.RESTSBOMStorageImage{}}
	st := s3store.Current()
	if st == nil {
		restRespSuccess(w, r, resp, acc, login, nil, "List SBOM storage images")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	objs, err := st.List(ctx)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Failed to list SBOM objects in S3")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
		return
	}
	byDigest := make(map[string]s3store.Object, len(objs))
	digests := make(map[string]bool, len(objs))
	for _, o := range objs {
		byDigest[o.Digest] = o
		digests[o.Digest] = true
	}

	for _, ref := range scanner.GetRegistryImagesByDigest(digests, acc) {
		// another registry can claim the same digest: list only objects written by this registry image
		if owned, err := st.Owned(ctx, ref.Digest, ref.Registry, ref.ImageID); err != nil {
			log.WithFields(log.Fields{"error": err}).Warn("Failed to read SBOM object in S3")
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
			return
		} else if !owned {
			continue
		}
		o := byDigest[ref.Digest]
		resp.Images = append(resp.Images, &api.RESTSBOMStorageImage{
			Registry: ref.Registry, ImageID: ref.ImageID, Digest: ref.Digest, Images: ref.Images,
			Size: o.Size, LastModified: o.LastModified.UTC().Format(time.RFC3339),
		})
	}
	restRespSuccess(w, r, resp, acc, login, nil, "List SBOM storage images")
}
