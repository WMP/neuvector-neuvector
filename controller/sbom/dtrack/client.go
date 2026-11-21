package dtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// ErrTooLarge means DT or a reverse proxy in front of it answered HTTP 413.
var ErrTooLarge = errors.New("SBOM rejected as too large")

const maxBody = 1 << 20

// Client talks to the Dependency-Track REST API.
// Facts from the DT source:
//   - POST /api/v1/bom (BomResource.java): multipart/form-data with autoCreate, projectName,
//     projectVersion, projectTags (one comma-separated string, DT 4.12+) and bom (plain JSON file part).
//     Header X-Api-Key. Answer 200 {"token":...}.
//   - GET /api/v1/project/lookup?name=&version= (ProjectResource.java): 200 project JSON, 404 when missing.
//   - GET .../lookup without the version parameter finds only projects without a version (version == null);
//     an empty version= would not match. Parents have no version, so the parameter is omitted for them.
//     The answer has uuid, active and parent{uuid} (ProjectResource.java, ProjectQueryFilterBuilder).
//   - PUT /api/v1/project {"name","parent":{"uuid"},"active":true}: 201 with uuid, 409 when it exists or the parent is inactive.
//   - PATCH /api/v1/project/{uuid} {"active":..,"parent":{"uuid":..}}: 200, 304 unchanged, 409 when active children
//     block it, when the new parent is inactive or on a cycle, 404 for an unknown parent. Parent: DT 4.8+.
//   - bom field parentUUID sets the parent only when the upload auto-creates the project (404 when the parent is
//     unknown); an existing project keeps its parent, so it needs a PATCH.
//   - DT has no own size limit. 413 comes from a reverse proxy (nginx ingress default is 1 MB).
//
// The API key is only sent in a header. Errors never contain request headers.
type Client struct {
	URL    string // base URL without trailing slash
	APIKey string
	HTTP   *http.Client
}

func (c *Client) do(req *http.Request) (int, []byte, error) {
	req.Header.Set("X-Api-Key", c.APIKey)
	var hc http.Client
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	// a redirect would send the X-Api-Key header to another host
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		// url.Error holds method and URL only, not headers.
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, body, err
}

// errRejected marks a client error (4xx except 408 and 429): a retry gives the same answer.
var errRejected = errors.New("rejected by Dependency-Track")

// errNotFound marks HTTP 404 (also errRejected).
var errNotFound = errors.New("not found in Dependency-Track")

func statusErr(what string, code int, body []byte) error {
	if len(body) > 200 {
		body = body[:200]
	}
	err := fmt.Errorf("%s: HTTP %d: %s", what, code, bytes.TrimSpace(body))
	if code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
		err = fmt.Errorf("%w: %w", errRejected, err)
	}
	if code == http.StatusNotFound {
		err = fmt.Errorf("%w: %w", errNotFound, err)
	}
	return err
}

// Upload sends bom as the project p. autoCreate makes DT create the project when needed.
func (c *Client) Upload(ctx context.Context, p Project, parentUUID string, bom []byte) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	var werr error // writes to a bytes.Buffer cannot fail; the first error is still returned
	field := func(k, v string) {
		if err := mw.WriteField(k, v); err != nil && werr == nil {
			werr = err
		}
	}
	field("autoCreate", "true")
	field("projectName", p.Name)
	field("projectVersion", p.Version)
	if parentUUID != "" {
		field("parentUUID", parentUUID) // only used by DT when it creates the project
	}
	if len(p.Tags) > 0 {
		field("projectTags", strings.Join(p.Tags, ","))
	}
	fw, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="bom"; filename="bom.json"`},
		"Content-Type":        {"application/json"},
	})
	if err != nil {
		return err
	}
	if _, err := fw.Write(bom); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	if werr != nil {
		return werr
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/v1/bom", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	code, body, err := c.do(req)
	switch {
	case err != nil:
		return fmt.Errorf("upload SBOM: %w", err)
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: Dependency-Track (or a proxy in front of it) rejected the SBOM of %d bytes as too large (HTTP 413); "+
			"raise the request body limit of the reverse proxy, e.g. nginx ingress annotation nginx.ingress.kubernetes.io/proxy-body-size",
			ErrTooLarge, len(bom))
	}
	return statusErr("upload SBOM", code, body)
}

// dtProject is the part of the DT project JSON that the uploader needs.
type dtProject struct {
	UUID       string
	Active     bool
	ParentUUID string
}

// lookup returns nil when the project does not exist. An empty version means "project without version"
// (the parameter is omitted, see Client).
func (c *Client) lookup(ctx context.Context, name, version string) (*dtProject, error) {
	q := url.Values{"name": {name}}
	if version != "" {
		q.Set("version", version)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/api/v1/project/lookup?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	code, body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup project: %w", err)
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	if code != http.StatusOK {
		return nil, statusErr("lookup project", code, body)
	}
	var proj struct {
		UUID   string `json:"uuid"`
		Active bool   `json:"active"`
		Parent *struct {
			UUID string `json:"uuid"`
		} `json:"parent"`
	}
	if err := json.Unmarshal(body, &proj); err != nil || proj.UUID == "" {
		return nil, fmt.Errorf("lookup project: bad answer")
	}
	p := &dtProject{UUID: proj.UUID, Active: proj.Active}
	if proj.Parent != nil {
		p.ParentUUID = proj.Parent.UUID
	}
	return p, nil
}

// create makes an active project without version. It returns the new project, or on 409 (created meanwhile) the existing one as it is in DT.
func (c *Client) create(ctx context.Context, name, parentUUID string) (*dtProject, error) {
	m := map[string]any{"name": name, "active": true}
	if parentUUID != "" {
		m["parent"] = map[string]string{"uuid": parentUUID}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.URL+"/api/v1/project", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	code, body, err := c.do(req)
	switch {
	case err != nil:
		return nil, fmt.Errorf("create project: %w", err)
	case code == http.StatusOK || code == http.StatusCreated:
		var proj struct {
			UUID   string `json:"uuid"`
			Parent *struct {
				UUID string `json:"uuid"`
			} `json:"parent"`
		}
		if err := json.Unmarshal(body, &proj); err != nil || proj.UUID == "" {
			return nil, fmt.Errorf("create project: bad answer")
		}
		// DT does not check an unknown parent UUID on create: the answer tells the parent it really set
		p := &dtProject{UUID: proj.UUID, Active: true}
		if proj.Parent != nil {
			p.ParentUUID = proj.Parent.UUID
		}
		return p, nil
	case code == http.StatusConflict:
		if p, lerr := c.lookup(ctx, name, ""); lerr == nil && p != nil {
			return p, nil
		}
	}
	return nil, statusErr("create project", code, body)
}

// patch changes the active flag (when not nil) and the parent (when not empty) of a project.
func (c *Client) patch(ctx context.Context, uuid string, active *bool, parentUUID string) error {
	m := map[string]any{}
	if active != nil {
		m["active"] = *active
	}
	if parentUUID != "" {
		m["parent"] = map[string]string{"uuid": parentUUID}
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.URL+"/api/v1/project/"+url.PathEscape(uuid), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	code, body, err := c.do(req)
	switch {
	case err != nil:
		return fmt.Errorf("update project: %w", err)
	case code == http.StatusOK || code == http.StatusNotModified:
		return nil
	case code == http.StatusConflict:
		return fmt.Errorf("%w: update project: HTTP 409: active child projects, an inactive parent or a cycle block the change", errRejected)
	}
	return statusErr("update project", code, body)
}

// SetActive sets the active flag of a project. A missing project is not an error.
// An empty version selects the project without version (a parent project).
func (c *Client) SetActive(ctx context.Context, name, version string, active bool) error {
	proj, err := c.lookup(ctx, name, version)
	if err != nil || proj == nil || proj.Active == active {
		return err
	}
	return c.patch(ctx, proj.UUID, &active, "")
}
