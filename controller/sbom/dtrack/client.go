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
//   - PATCH /api/v1/project/{uuid} {"active":false}: 200, 304 unchanged, 409 when active children block it.
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

func statusErr(what string, code int, body []byte) error {
	if len(body) > 200 {
		body = body[:200]
	}
	err := fmt.Errorf("%s: HTTP %d: %s", what, code, bytes.TrimSpace(body))
	if code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
		err = fmt.Errorf("%w: %w", errRejected, err)
	}
	return err
}

// Upload sends bom as the project p. autoCreate makes DT create the project when needed.
func (c *Client) Upload(ctx context.Context, p Project, bom []byte) error {
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

// SetActive sets the active flag of a project. A missing project is not an error.
func (c *Client) SetActive(ctx context.Context, name, version string, active bool) error {
	q := url.Values{"name": {name}, "version": {version}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"/api/v1/project/lookup?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	code, body, err := c.do(req)
	if err != nil {
		return fmt.Errorf("lookup project: %w", err)
	}
	if code == http.StatusNotFound {
		return nil
	}
	if code != http.StatusOK {
		return statusErr("lookup project", code, body)
	}
	var proj struct {
		UUID   string `json:"uuid"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal(body, &proj); err != nil || proj.UUID == "" {
		return fmt.Errorf("lookup project: bad answer")
	}
	if proj.Active == active {
		return nil
	}
	data, err := json.Marshal(map[string]bool{"active": active})
	if err != nil {
		return err
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodPatch, c.URL+"/api/v1/project/"+url.PathEscape(proj.UUID), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	code, body, err = c.do(req)
	switch {
	case err != nil:
		return fmt.Errorf("update project: %w", err)
	case code == http.StatusOK || code == http.StatusNotModified:
		return nil
	case code == http.StatusConflict:
		return fmt.Errorf("update project: HTTP 409: active child projects block the change")
	}
	return statusErr("update project", code, body)
}
