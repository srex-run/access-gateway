package cloudassets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (c *Client) huawei(ctx context.Context, credentials Credentials, region string) ([]Instance, error) {
	var projects struct {
		Projects []struct {
			ID, Name string
			Enabled  bool
		} `json:"projects"`
	}
	if err := c.huaweiGet(ctx, credentials, "https://iam.myhuaweicloud.com/v3/projects?"+url.Values{"name": {region}}.Encode(), &projects); err != nil {
		return nil, err
	}
	projectID := ""
	for _, project := range projects.Projects {
		if project.Name == region && project.Enabled && ValidInstanceID(project.ID) {
			if projectID != "" {
				return nil, &Error{Code: "ambiguous_project"}
			}
			projectID = project.ID
		}
	}
	if projectID == "" {
		return nil, &Error{Code: "region_unavailable"}
	}
	var values []Instance
	seen := make(map[string]bool)
	for page := 0; page < 200; page++ {
		query := url.Values{"limit": {"1000"}, "offset": {strconv.Itoa(page * 1000)}}
		var response struct {
			Count   *int `json:"count"`
			Servers *[]struct {
				ID, Name  string
				Addresses map[string][]struct {
					Address string `json:"addr"`
					Type    string `json:"OS-EXT-IPS:type"`
				} `json:"addresses"`
			} `json:"servers"`
		}
		endpoint := "https://ecs." + region + ".myhuaweicloud.com/v1/" + projectID + "/cloudservers/detail?" + query.Encode()
		if err := c.huaweiGet(ctx, credentials, endpoint, &response); err != nil {
			return nil, err
		}
		if response.Servers == nil || response.Count == nil {
			return nil, &Error{Code: "invalid_response"}
		}
		for _, instance := range *response.Servers {
			if seen[instance.ID] {
				return nil, &Error{Code: "incomplete_pagination"}
			}
			seen[instance.ID] = true
			value := Instance{ID: instance.ID, Name: instance.Name}
			var networks []string
			for network := range instance.Addresses {
				networks = append(networks, network)
			}
			sort.Strings(networks)
			for _, network := range networks {
				for _, address := range instance.Addresses[network] {
					if address.Type == "fixed" && value.Host == "" {
						value.Host = address.Address
					}
				}
			}
			values = append(values, value)
		}
		if len(values) > MaxInstances {
			return nil, &Error{Code: "too_many_instances"}
		}
		if len(values) >= *response.Count {
			return values, nil
		}
		if len(*response.Servers) == 0 {
			return nil, &Error{Code: "incomplete_pagination"}
		}
	}
	return nil, &Error{Code: "incomplete_pagination"}
}

func (c *Client) huaweiGet(ctx context.Context, credentials Credentials, endpoint string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return apiError(err)
	}
	request.Header.Set("X-Sdk-Date", time.Now().UTC().Format("20060102T150405Z"))
	request.Header.Set("Authorization", huaweiSignature(request, credentials))
	response, err := c.http.Do(request)
	if err != nil {
		return apiError(err)
	}
	defer response.Body.Close()
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return &Error{Code: "credentials_or_permissions"}
	}
	if response.StatusCode == 429 {
		return &Error{Code: "rate_limited"}
	}
	if response.StatusCode != http.StatusOK {
		return &Error{Code: "api_request_failed"}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil {
		return apiError(err)
	}
	if len(data) > 8<<20 || json.Unmarshal(data, output) != nil {
		return &Error{Code: "invalid_response"}
	}
	return nil
}

// SDK-HMAC-SHA256 signing requires a trailing slash in the canonical URI.
func huaweiSignature(request *http.Request, credentials Credentials) string {
	date := request.Header.Get("X-Sdk-Date")
	path := strings.TrimSuffix(request.URL.EscapedPath(), "/") + "/"
	headers := "host:" + request.URL.Host + "\nx-sdk-date:" + date + "\n"
	canonical := strings.Join([]string{http.MethodGet, path, request.URL.RawQuery, headers, "host;x-sdk-date", sha256Hex(nil)}, "\n")
	toSign := "SDK-HMAC-SHA256\n" + date + "\n" + sha256Hex([]byte(canonical))
	mac := hmac.New(sha256.New, []byte(credentials.SecretKey))
	_, _ = mac.Write([]byte(toSign))
	return "SDK-HMAC-SHA256 Access=" + credentials.AccessKey + ", SignedHeaders=host;x-sdk-date, Signature=" + hex.EncodeToString(mac.Sum(nil))
}

func sha256Hex(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
