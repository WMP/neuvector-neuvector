package rest

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/sbom"
	"github.com/neuvector/neuvector/controller/sbom/s3store"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

// sbomPrepare does the permission and format checks common to all SBOM handlers.
// It writes the error response and returns ok=false when the request must stop.
func sbomPrepare(w http.ResponseWriter, r *http.Request) (acc *access.AccessControl, login *loginSession, format string, ok bool) {
	acc, login = getAccessControl(w, r, "")
	if acc == nil {
		return nil, nil, "", false
	}
	// the user has the sbom permission in no domain
	if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return nil, nil, "", false
	}

	format = sbom.FormatCycloneDX
	if v := restParseQuery(r).pairs["format"]; v != "" {
		format = v
	}
	if _, valid := sbom.ContentType(format); !valid {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unsupported SBOM format")
		return nil, nil, "", false
	}
	return acc, login, format, true
}

// sbomRespond encodes the document into memory first so that an error never leaves a partial body.
func sbomRespond(w http.ResponseWriter, format string, meta sbom.Meta, modules []*share.ScanModule, namespace string, image []*share.ScanModule) {
	meta.Cluster = cacher.GetSystemConfigClusterName(access.NewReaderAccessControl())
	meta.Created = time.Now().UTC()
	meta.Serial = uuid.New().String()

	var buf bytes.Buffer
	if err := sbom.Write(&buf, format, meta, sbom.Components(modules, namespace, image)); err != nil {
		log.WithFields(log.Fields{"id": meta.ID, "format": format, "error": err}).Error("Failed to generate SBOM")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailExport)
		return
	}

	sbomHeaders(w, format)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Write")
	}
	log.WithFields(log.Fields{"id": meta.ID, "format": format}).Debug("SBOM downloaded")
}

func sbomHeaders(w http.ResponseWriter, format string) {
	ct, _ := sbom.ContentType(format)
	filename := "sbom.cdx.json"
	if format == sbom.FormatSPDX {
		filename = "sbom.spdx.json"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
}

// sbomFromS3 sends the stored full CycloneDX document of the registry image sum (access already checked).
// It returns false when the caller must build the document.
func sbomFromS3(w http.ResponseWriter, r *http.Request, sum *share.CLUSRegistryImageSummary, meta sbom.Meta) bool {
	digest := sum.Digest
	st := s3store.Current()
	if st == nil || !s3store.ValidDigest(digest) {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second) // a down S3 must not hold the fallback long
	defer cancel()
	select { // each download holds the object in memory
	case sbomS3Downloads <- struct{}{}:
		defer func() { <-sbomS3Downloads }()
	case <-ctx.Done():
		log.WithFields(log.Fields{"digest": digest}).Warn("Too many SBOM downloads from S3")
		return false
	}
	rc, err := st.Open(ctx, digest, sum.RegName, sum.ImageID)
	if err != nil {
		if errors.Is(err, s3store.ErrNotFound) || errors.Is(err, s3store.ErrNotOwner) {
			log.WithFields(log.Fields{"digest": digest}).Debug("SBOM not in S3")
		} else {
			log.WithFields(log.Fields{"digest": digest, "error": err}).Warn("Failed to read SBOM from S3")
		}
		return false
	}
	// The upload is limited to MaxObjectSize. The whole gzip stream is checked (CRC) before
	// the status is sent, so a damaged object falls back to the inventory instead of a cut 200 body.
	zb, err := io.ReadAll(io.LimitReader(rc, s3store.MaxObjectSize+1))
	rc.Close()
	if err == nil && len(zb) > s3store.MaxObjectSize {
		err = errors.New("object too large")
	}
	if err == nil {
		err = gunzipTo(io.Discard, zb)
	}
	if err != nil {
		log.WithFields(log.Fields{"digest": digest, "error": err}).Warn("Invalid SBOM in S3")
		return false
	}

	sbomHeaders(w, sbom.FormatCycloneDX)
	w.WriteHeader(http.StatusOK)
	if err := gunzipTo(w, zb); err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Write")
	}
	log.WithFields(log.Fields{"id": meta.ID, "format": sbom.FormatCycloneDX}).Debug("SBOM downloaded from S3")
	return true
}

var sbomS3Downloads = make(chan struct{}, 4)

const sbomS3MaxJSON = 256 << 20 // uncompressed; a full Syft document of 15 000 components is about 18 MB

func gunzipTo(w io.Writer, zb []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(zb))
	if err != nil {
		return err
	}
	defer gz.Close()
	n, err := io.Copy(w, io.LimitReader(gz, sbomS3MaxJSON+1))
	if err == nil && n > sbomS3MaxJSON {
		err = errors.New("document too large")
	}
	return err
}

// sbomRespErr writes the error response; err.Error() is never sent to the client.
func sbomRespErr(w http.ResponseWriter, login *loginSession, err error) {
	switch {
	case errors.Is(err, common.ErrObjectAccessDenied):
		restRespNotFoundLogAccessDenied(w, login, err)
	case errors.Is(err, common.ErrObjectNotFound):
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
	default:
		log.WithFields(log.Fields{"error": err}).Error("Failed to get SBOM data")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailReadCluster)
	}
}

// imageScanModules returns the modules and summary of the image scan the user can access; nil when there is none.
func imageScanModules(acc *access.AccessControl, imageID string) ([]*share.ScanModule, *share.CLUSRegistryImageSummary) {
	if imageID == "" {
		return nil, nil
	}
	modules, sum, err := scanner.GetRegistryImageModules(common.RegistryAllName, imageID, acc)
	if err != nil || sum == nil {
		return nil, nil
	}
	if modules == nil { // a scan with no modules still exists: everything in the container is runtime
		modules = []*share.ScanModule{}
	}
	return modules, sum
}

// sbomWorkload serves the SBOM of the scanned workload id. For SourceImage the image scan is used when accessible.
func sbomWorkload(w http.ResponseWriter, r *http.Request, acc *access.AccessControl, login *loginSession, format, id, source, name string) {
	wl, err := cacher.GetWorkload(id, "", acc)
	if err != nil || wl == nil {
		sbomRespErr(w, login, err)
		return
	}
	if name == "" {
		name = wl.PodName
		if name == "" {
			name = wl.DisplayName
		}
		if name == "" {
			name = wl.Name
		}
	}
	meta := sbom.Meta{Source: source, Name: name, ID: id, Digest: wl.ImageDigest}
	imgModules, sum := imageScanModules(acc, wl.ImageID)
	if source == sbom.SourceImage && sum != nil { // the image scan is the image content
		if sum.Digest != "" {
			meta.Digest = sum.Digest
		}
		if format == sbom.FormatCycloneDX && sbomFromS3(w, r, sum, meta) {
			return
		}
		sbomRespond(w, format, meta, imgModules, sum.BaseOS, nil)
		return
	}
	modules, baseOS, err := cacher.GetScanModules(id)
	if err != nil {
		sbomRespErr(w, login, err)
		return
	}
	if source == sbom.SourceImage {
		sbomRespond(w, format, meta, modules, baseOS, nil)
		return
	}
	meta.Domain = wl.Domain // an image can run in several namespaces, so only a container has a domain
	sbomRespond(w, format, meta, modules, baseOS, imgModules)
}

func handlerScanWorkloadSBOM(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login, format, ok := sbomPrepare(w, r)
	if !ok {
		return
	}
	sbomWorkload(w, r, acc, login, format, ps.ByName("id"), sbom.SourceContainer, "")
}

func handlerScanImageSBOM(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login, format, ok := sbomPrepare(w, r)
	if !ok {
		return
	}

	id := ps.ByName("id")
	var brief *api.RESTWorkloadBrief
	for _, wl := range cacher.GetAllWorkloadsBrief("", acc) {
		// lowest workload ID: the same request always gives the same document
		if wl.ImageID == id && wl.ScanSummary != nil && wl.ScanSummary.Status == api.ScanStatusFinished &&
			wl.ScanSummary.Result == scanUtils.ScanErrorToStr(share.ScanErrorCode_ScanErrNone) && (brief == nil || wl.ID < brief.ID) {
			brief = wl
		}
	}
	if brief == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}
	sbomWorkload(w, r, acc, login, format, brief.ID, sbom.SourceImage, brief.Image)
}

func handlerScanHostSBOM(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login, format, ok := sbomPrepare(w, r)
	if !ok {
		return
	}

	id := ps.ByName("id")
	host, err := cacher.GetHost(id, acc)
	if err != nil || host == nil {
		sbomRespErr(w, login, err)
		return
	}
	modules, baseOS, err := cacher.GetScanModules(id)
	if err != nil {
		sbomRespErr(w, login, err)
		return
	}
	sbomRespond(w, format, sbom.Meta{Source: sbom.SourceHost, Name: host.Name, ID: id}, modules, baseOS, nil)
}

func handlerRegistryImageSBOM(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login, format, ok := sbomPrepare(w, r)
	if !ok {
		return
	}

	id := ps.ByName("id")
	modules, sum, err := scanner.GetRegistryImageModules(ps.ByName("name"), id, acc)
	if err != nil || sum == nil {
		sbomRespErr(w, login, err)
		return
	}
	name := id
	for _, img := range sum.Images { // lowest repo:tag: the same request always gives the same name
		if img.Repo == "" {
			continue
		}
		n := img.Repo
		if img.Tag != "" {
			n += ":" + img.Tag
		}
		if name == id || n < name {
			name = n
		}
	}
	meta := sbom.Meta{Source: sbom.SourceImage, Name: name, ID: id, Digest: sum.Digest}
	if format == sbom.FormatCycloneDX && sbomFromS3(w, r, sum, meta) {
		return
	}
	sbomRespond(w, format, meta, modules, sum.BaseOS, nil)
}
