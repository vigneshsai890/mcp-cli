package installer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

const maxRegistryResponse = 2 << 20

var sha256RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

type Resolution struct {
	Package  string         `json:"package"`
	Source   SourceMetadata `json:"source"`
	Manifest ManifestMeta   `json:"manifest"`
}

type SourceMetadata struct {
	URL    string `json:"url"`
	Commit string `json:"commit"`
}

type ManifestMeta struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type SearchResult struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type searchResponse struct {
	Results []SearchResult `json:"results"`
}

type Registry struct {
	base    *url.URL
	allowed map[string]struct{}
	client  *http.Client
}

func NewRegistry(baseURL string, allowedHosts []string) (*Registry, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse registry URL: %w", err)
	}
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		allowed[strings.ToLower(host)] = struct{}{}
	}
	r := &Registry{base: base, allowed: allowed}
	if err := r.validateRegistryURL(base); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid registry address: %w", err)
			}
			if _, ok := allowed[strings.ToLower(host)]; !ok {
				return nil, fmt.Errorf("registry host %q is not allowlisted", host)
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("resolve registry host: %w", err)
			}
			for _, ip := range ips {
				if unsafeIP(ip) {
					continue
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			return nil, fmt.Errorf("registry host resolved only to private or unsafe addresses")
		},
	}
	r.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return r.validateRegistryURL(req.URL)
		},
	}
	return r, nil
}

func (r *Registry) Resolve(ctx context.Context, spec Spec) (Resolution, error) {
	u := *r.base
	u.Path = path.Join(r.base.Path, "/v1/resolve")
	q := u.Query()
	q.Set("package", spec.Raw)
	u.RawQuery = q.Encode()
	data, err := r.get(ctx, &u)
	if err != nil {
		return Resolution{}, err
	}
	var result Resolution
	if err := decodeStrict(data, &result); err != nil {
		return Resolution{}, fmt.Errorf("invalid resolution metadata: %w", err)
	}
	if err := validateResolution(spec, result, r); err != nil {
		return Resolution{}, err
	}
	return result, nil
}

func (r *Registry) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if query == "" || len(query) > 256 {
		return nil, fmt.Errorf("query must contain 1 to 256 characters")
	}
	u := *r.base
	u.Path = path.Join(r.base.Path, "/v1/search")
	q := u.Query()
	q.Set("q", query)
	u.RawQuery = q.Encode()
	data, err := r.get(ctx, &u)
	if err != nil {
		return nil, err
	}
	var result searchResponse
	if err := decodeStrict(data, &result); err != nil {
		return nil, fmt.Errorf("invalid search response: %w", err)
	}
	for _, item := range result.Results {
		if !centralNameRE.MatchString(item.Name) || item.Version == "" {
			return nil, fmt.Errorf("registry returned an invalid search result")
		}
	}
	return result.Results, nil
}

func (r *Registry) FetchVerifiedManifest(ctx context.Context, meta ManifestMeta) ([]byte, error) {
	if !sha256RE.MatchString(meta.SHA256) {
		return nil, fmt.Errorf("trusted metadata contains an invalid manifest SHA-256")
	}
	u, err := url.Parse(meta.URL)
	if err != nil || r.validateRegistryURL(u) != nil {
		return nil, fmt.Errorf("manifest URL is not on the HTTPS registry allowlist")
	}
	data, err := r.get(ctx, u)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), meta.SHA256) {
		return nil, fmt.Errorf("manifest SHA-256 does not match trusted registry metadata")
	}
	return data, nil
}

func (r *Registry) get(ctx context.Context, u *url.URL) ([]byte, error) {
	if err := r.validateRegistryURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRegistryResponse+1))
	if err != nil {
		return nil, fmt.Errorf("read registry response: %w", err)
	}
	if len(data) > maxRegistryResponse {
		return nil, fmt.Errorf("registry response too large")
	}
	return data, nil
}

func (r *Registry) validateRegistryURL(u *url.URL) error {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
		return fmt.Errorf("registry URLs must be HTTPS without user information")
	}
	if u.Port() != "" && u.Port() != "443" {
		return fmt.Errorf("registry URL port must be 443")
	}
	if _, ok := r.allowed[strings.ToLower(u.Hostname())]; !ok {
		return fmt.Errorf("registry host %q is not allowlisted", u.Hostname())
	}
	return nil
}

func validateResolution(spec Spec, m Resolution, r *Registry) error {
	if !centralNameRE.MatchString(m.Package) || !sha256RE.MatchString(m.Manifest.SHA256) {
		return fmt.Errorf("registry metadata has an invalid package identity or manifest SHA-256")
	}
	manifestURL, err := url.Parse(m.Manifest.URL)
	if err != nil || r.validateRegistryURL(manifestURL) != nil {
		return fmt.Errorf("registry metadata has a non-allowlisted manifest URL")
	}
	commit := strings.ToLower(m.Source.Commit)
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit) {
		return fmt.Errorf("source must be pinned to a full 40-hex commit")
	}
	sourceURL, err := url.Parse(m.Source.URL)
	if err != nil || sourceURL.Scheme != "https" || strings.ToLower(sourceURL.Hostname()) != "github.com" || sourceURL.User != nil || (sourceURL.Port() != "" && sourceURL.Port() != "443") || sourceURL.RawQuery != "" || sourceURL.Fragment != "" || sourceURL.Opaque != "" || sourceURL.ForceQuery || sourceURL.EscapedPath() != sourceURL.Path {
		return fmt.Errorf("source must be a canonical HTTPS github.com repository URL")
	}
	if sourceURL.Path == "" || sourceURL.Path != strings.TrimSuffix(sourceURL.Path, "/") {
		return fmt.Errorf("source must identify exactly one canonical GitHub owner/repository")
	}
	parts := strings.Split(strings.TrimPrefix(sourceURL.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.HasSuffix(strings.ToLower(parts[1]), ".git") {
		return fmt.Errorf("source must identify exactly one canonical GitHub owner/repository without .git")
	}
	metadataSpec, err := ParseSpec(parts[0] + "/" + parts[1] + "@" + commit)
	if err != nil || metadataSpec.Kind != "github" {
		return fmt.Errorf("source contains an invalid GitHub owner or repository")
	}
	if spec.Kind == "github" {
		if !strings.EqualFold(parts[0], spec.Owner) || !strings.EqualFold(parts[1], spec.Repository) || commit != spec.Commit {
			return fmt.Errorf("trusted metadata does not match the requested GitHub repository and commit")
		}
	} else if m.Package != spec.Name {
		return fmt.Errorf("trusted metadata package does not match request")
	}
	return nil
}

func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func unsafeIP(ip netip.Addr) bool {
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
