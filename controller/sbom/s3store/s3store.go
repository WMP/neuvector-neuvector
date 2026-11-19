// Package s3store keeps full SBOM documents (gzip CycloneDX JSON) in an S3-compatible bucket.
package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httpclient"
)

const (
	DefaultRegion       = "us-east-1"
	DefaultGraceMinutes = 1440
	MaxGraceMinutes     = 525600
	MaxObjectSize       = 32 << 20 // gzip; the scanner leaves out a larger SBOM so the result stays below the gRPC limit

	objSuffix = ".cdx.json.gz"
)

var ErrNotFound = errors.New("SBOM object not found")

var (
	digestRe = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$`)
	regionRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
)

func ValidDigest(d string) bool { return digestRe.MatchString(d) }

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// Validate checks the configuration. Messages never contain the secret key.
func Validate(cfg share.CLUSSBOMStorage) error {
	if cfg.Endpoint != "" {
		if strings.ContainsAny(cfg.Endpoint, "#?") {
			return errors.New("endpoint must not contain query or fragment")
		}
		u, err := url.Parse(cfg.Endpoint)
		if err != nil {
			return errors.New("endpoint is not a valid URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return errors.New("endpoint scheme must be http or https")
		}
		if u.Host == "" || u.Hostname() == "" {
			return errors.New("endpoint host is empty")
		}
		if u.User != nil {
			return errors.New("endpoint must not contain user info")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return errors.New("endpoint must not contain query or fragment")
		}
		if u.Path != "" && u.Path != "/" {
			return errors.New("endpoint must not contain a path")
		}
	}
	if cfg.Region != "" && !regionRe.MatchString(cfg.Region) {
		return errors.New("invalid region")
	}
	if cfg.Bucket == "" {
		if cfg.Enabled {
			return errors.New("bucket is required")
		}
	} else if len(cfg.Bucket) < 3 || len(cfg.Bucket) > 63 || !bucketRe.MatchString(cfg.Bucket) || strings.Contains(cfg.Bucket, "..") {
		return errors.New("invalid bucket name")
	}
	if len(cfg.Prefix) > 256 || hasControl(cfg.Prefix) || strings.Contains(cfg.Prefix, `\`) {
		return errors.New("invalid prefix")
	}
	if p := strings.Trim(cfg.Prefix, "/"); p != "" {
		for _, seg := range strings.Split(p, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return errors.New("invalid prefix")
			}
		}
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return errors.New("access key and secret key must be set together")
	}
	for _, k := range []string{cfg.AccessKey, cfg.SecretKey} {
		if hasControl(k) || strings.TrimSpace(k) != k {
			return errors.New("invalid access key or secret key characters")
		}
	}
	if cfg.DeleteGrace > MaxGraceMinutes {
		return fmt.Errorf("delete grace period must be at most %d minutes", MaxGraceMinutes)
	}
	return nil
}

type Object struct {
	Digest       string
	Size         int64
	LastModified time.Time
}

type Store struct {
	api    *s3.S3
	bucket string
	base   string // "<prefix>/<cluster>/images/"

	DeleteUnused bool
	Grace        time.Duration
}

// New validates the config and builds a store. It makes no network call.
func New(cfg share.CLUSSBOMStorage, cluster string, hc *http.Client) (*Store, error) {
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	if cfg.Bucket == "" {
		return nil, errors.New("bucket is required")
	}
	if cluster == "" || cluster == "." || cluster == ".." {
		return nil, errors.New("invalid cluster name")
	}
	base := url.PathEscape(cluster) + "/images/"
	if p := strings.Trim(cfg.Prefix, "/"); p != "" {
		base = p + "/" + base
	}

	region := cfg.Region
	if region == "" {
		region = DefaultRegion
	}
	awsCfg := aws.NewConfig().WithHTTPClient(hc).WithRegion(region).WithS3ForcePathStyle(cfg.PathStyle).WithMaxRetries(2)
	if cfg.Endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(cfg.Endpoint)
	}
	if cfg.AccessKey != "" {
		awsCfg = awsCfg.WithCredentials(credentials.NewStaticCredentials(cfg.AccessKey, cfg.SecretKey, ""))
	}
	sess, err := session.NewSession(awsCfg)
	if err != nil {
		return nil, fmt.Errorf("cannot create S3 session: %w", err)
	}

	s := &Store{api: s3.New(sess), bucket: cfg.Bucket, base: base, DeleteUnused: cfg.DeleteUnused}
	grace := cfg.DeleteGrace
	if grace == 0 {
		grace = DefaultGraceMinutes
	}
	s.Grace = time.Duration(grace) * time.Minute
	return s, nil
}

func (s *Store) Key(digest string) (string, error) {
	if !ValidDigest(digest) {
		return "", errors.New("invalid image digest")
	}
	return s.base + digest + objSuffix, nil
}

func (s *Store) Put(ctx context.Context, digest string, gz []byte) error {
	key, err := s.Key(digest)
	if err != nil {
		return err
	}
	_, err = s.api.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(gz),
		ContentType: aws.String("application/gzip"),
	})
	if err != nil {
		return fmt.Errorf("SBOM put failed: %w", err)
	}
	return nil
}

func (s *Store) Open(ctx context.Context, digest string) (io.ReadCloser, error) {
	key, err := s.Key(digest)
	if err != nil {
		return nil, err
	}
	out, err := s.api.GetObjectWithContext(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		var ae awserr.RequestFailure
		if errors.As(err, &ae) && (ae.Code() == s3.ErrCodeNoSuchKey || (ae.StatusCode() == http.StatusNotFound && ae.Code() != s3.ErrCodeNoSuchBucket)) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("SBOM get failed: %w", err)
	}
	return out.Body, nil
}

func (s *Store) Delete(ctx context.Context, digest string) error {
	key, err := s.Key(digest)
	if err != nil {
		return err
	}
	if _, err = s.api.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("SBOM delete failed: %w", err)
	}
	return nil
}

// List returns only objects named exactly "<base><valid digest>.cdx.json.gz".
func (s *Store) List(ctx context.Context) ([]Object, error) {
	var objs []Object
	err := s.api.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(s.bucket), Prefix: aws.String(s.base)},
		func(p *s3.ListObjectsV2Output, _ bool) bool {
			for _, o := range p.Contents {
				rest, ok := strings.CutPrefix(aws.StringValue(o.Key), s.base)
				if !ok {
					continue
				}
				d, ok := strings.CutSuffix(rest, objSuffix)
				if !ok || !ValidDigest(d) {
					continue
				}
				objs = append(objs, Object{Digest: d, Size: aws.Int64Value(o.Size), LastModified: aws.TimeValue(o.LastModified)})
			}
			return true
		})
	if err != nil {
		return nil, fmt.Errorf("SBOM list failed: %w", err)
	}
	return objs, nil
}

// process-wide current store

type confKey struct {
	Cfg         share.CLUSSBOMStorage
	Cluster     string
	TLSVerify   bool
	CaCerts     []string
	Http, Https share.CLUSProxy
}

var (
	mu      sync.RWMutex
	current *Store
	last    *confKey
)

func Current() *Store {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Configure rebuilds the current store when the relevant part of the system config changed.
func Configure(cfg *share.CLUSSystemConfig) {
	key := &confKey{cfg.SBOMStorage, cfg.ClusterName, cfg.EnableTLSVerification, cfg.GlobalCaCerts, cfg.RegistryHttpProxy, cfg.RegistryHttpsProxy}
	mu.Lock()
	defer mu.Unlock()
	if last != nil && reflect.DeepEqual(last, key) {
		return
	}
	last = key
	current = nil
	sc := cfg.SBOMStorage
	if !sc.Enabled {
		return
	}
	st, err := build(sc, cfg.ClusterName)
	if err != nil {
		log.WithFields(log.Fields{"endpoint": sc.Endpoint, "bucket": sc.Bucket, "error": err}).Warn("sbom s3: storage disabled")
		last = nil // retry on the next update
		return
	}
	current = st
	log.WithFields(log.Fields{"endpoint": sc.Endpoint, "bucket": sc.Bucket, "prefix": sc.Prefix, "path_style": sc.PathStyle}).Info("sbom s3: storage enabled")
}

// bypassMetadata keeps the instance and container metadata endpoints off the registry proxy: with empty keys
// the default AWS credential chain uses this client to get the role credentials.
func bypassMetadata(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		h := r.URL.Hostname()
		if ip := net.ParseIP(h); ip != nil && (ip.IsLinkLocalUnicast() || ip.Equal(net.ParseIP("fd00:ec2::254"))) {
			return nil, nil
		}
		return proxy(r)
	}
}

func build(sc share.CLUSSBOMStorage, cluster string) (*Store, error) {
	if err := Validate(sc); err != nil {
		return nil, err
	}
	proxy := httpclient.GetHttpsProxy()
	if strings.HasPrefix(strings.ToLower(sc.Endpoint), "http://") {
		proxy = httpclient.GetHttpProxy()
	}
	base, err := httpclient.CreateHTTPClient(proxy)
	if err != nil {
		return nil, err
	}
	hc := *base
	if t, ok := base.Transport.(*http.Transport); ok && t.Proxy != nil {
		t = t.Clone()
		t.Proxy = bypassMetadata(t.Proxy)
		hc.Transport = t
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hc.Timeout = 5 * time.Minute
	return New(sc, cluster, &hc)
}
