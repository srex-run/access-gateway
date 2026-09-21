package cmdb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	contractVersion = 1
	pageSize        = 500
	maxPages        = 100
	maxAssets       = 5000
	maxResponseSize = 4 << 20
)

type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Asset struct {
	ExternalID    string   `json:"external_id"`
	RegionCode    string   `json:"region_code"`
	GatewayIDs    []string `json:"gateway_ids"`
	Name          string   `json:"name"`
	AssetType     string   `json:"asset_type"`
	Target        string   `json:"target"`
	RiskLevel     string   `json:"risk_level"`
	MaxTTLSeconds int      `json:"max_ttl_seconds"`
	Status        string   `json:"status"`
	Ports         []Port   `json:"ports"`
}

type Snapshot struct {
	Revision      string
	Authoritative bool
	Assets        []Asset
}

type Client interface {
	FetchSnapshot(ctx context.Context) (Snapshot, error)
}

type HTTPClientConfig struct {
	Endpoint    string
	BearerToken string
	Timeout     time.Duration
	AllowHTTP   bool
}

type HTTPClient struct {
	endpoint    *url.URL
	bearerToken string
	client      *http.Client
}

type pageResponse struct {
	Version       int     `json:"version"`
	Revision      string  `json:"revision"`
	Authoritative bool    `json:"authoritative"`
	Assets        []Asset `json:"assets"`
	NextCursor    string  `json:"next_cursor"`
}

func NewHTTPClient(config HTTPClientConfig) (*HTTPClient, error) {
	parsed, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("CMDB endpoint is invalid")
	}
	if parsed.Scheme != "https" && !config.AllowHTTP {
		return nil, fmt.Errorf("CMDB endpoint must use HTTPS")
	}
	if strings.TrimSpace(config.BearerToken) == "" {
		return nil, fmt.Errorf("CMDB bearer token is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	return &HTTPClient{
		endpoint:    parsed,
		bearerToken: strings.TrimSpace(config.BearerToken),
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: otelhttp.NewTransport(transport),
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *HTTPClient) FetchSnapshot(ctx context.Context) (Snapshot, error) {
	if c == nil || c.endpoint == nil || c.client == nil {
		return Snapshot{}, fmt.Errorf("CMDB client is not configured")
	}
	result := Snapshot{Assets: make([]Asset, 0)}
	seenAssets := make(map[string]struct{})
	seenCursors := make(map[string]struct{})
	cursor := ""
	for page := 0; page < maxPages; page++ {
		response, err := c.fetchPage(ctx, cursor)
		if err != nil {
			return Snapshot{}, err
		}
		if response.Version != contractVersion || !response.Authoritative {
			return Snapshot{}, fmt.Errorf("CMDB response is not an authoritative version %d snapshot", contractVersion)
		}
		response.Revision = strings.TrimSpace(response.Revision)
		if !validControlText(response.Revision, 256) {
			return Snapshot{}, fmt.Errorf("CMDB revision is invalid")
		}
		if result.Revision == "" {
			result.Revision = response.Revision
		} else if response.Revision != result.Revision {
			return Snapshot{}, fmt.Errorf("CMDB revision changed during pagination")
		}
		for _, asset := range response.Assets {
			externalID := strings.TrimSpace(asset.ExternalID)
			if externalID == "" {
				return Snapshot{}, fmt.Errorf("CMDB asset external ID is required")
			}
			if _, exists := seenAssets[externalID]; exists {
				return Snapshot{}, fmt.Errorf("CMDB snapshot contains a duplicate asset")
			}
			seenAssets[externalID] = struct{}{}
			result.Assets = append(result.Assets, asset)
			if len(result.Assets) > maxAssets {
				return Snapshot{}, fmt.Errorf("CMDB snapshot exceeds %d assets", maxAssets)
			}
		}
		cursor = strings.TrimSpace(response.NextCursor)
		if cursor == "" {
			result.Authoritative = true
			return result, nil
		}
		if !validControlText(cursor, 2048) {
			return Snapshot{}, fmt.Errorf("CMDB pagination cursor is invalid")
		}
		if _, exists := seenCursors[cursor]; exists {
			return Snapshot{}, fmt.Errorf("CMDB pagination cursor repeated")
		}
		seenCursors[cursor] = struct{}{}
	}
	return Snapshot{}, fmt.Errorf("CMDB snapshot exceeds %d pages", maxPages)
}

func (c *HTTPClient) fetchPage(ctx context.Context, cursor string) (pageResponse, error) {
	requestURL := *c.endpoint
	query := requestURL.Query()
	query.Set("limit", strconv.Itoa(pageSize))
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	requestURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return pageResponse{}, fmt.Errorf("build CMDB request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.bearerToken)
	response, err := c.client.Do(request)
	if err != nil {
		return pageResponse{}, fmt.Errorf("send CMDB request: endpoint unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return pageResponse{}, fmt.Errorf("CMDB returned HTTP status %d", response.StatusCode)
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
	if err != nil {
		return pageResponse{}, fmt.Errorf("read CMDB response: %w", err)
	}
	defer clear(encoded)
	if len(encoded) > maxResponseSize {
		return pageResponse{}, fmt.Errorf("CMDB response exceeds %d bytes", maxResponseSize)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value pageResponse
	if err := decoder.Decode(&value); err != nil {
		return pageResponse{}, fmt.Errorf("decode CMDB response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return pageResponse{}, fmt.Errorf("decode CMDB response: trailing JSON data")
	}
	return value, nil
}

func validControlText(value string, maximum int) bool {
	return value != "" && len([]rune(value)) <= maximum && strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character)
	}) < 0
}
