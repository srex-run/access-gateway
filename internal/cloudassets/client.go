// Package cloudassets discovers private cloud hosts through read-only APIs.
package cloudassets

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const MaxInstances = 10000

var regionPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)
var instancePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

func ValidRegion(value string) bool     { return regionPattern.MatchString(value) }
func ValidInstanceID(value string) bool { return instancePattern.MatchString(value) }
func ValidProvider(value string) bool {
	return value == "aliyun" || value == "aws" || value == "huaweicloud"
}

type Credentials struct {
	AccessKey    string `json:"access_key"`
	SecretKey    string `json:"secret_key"`
	SessionToken string `json:"session_token,omitempty"`
}

type Instance struct {
	ID   string
	Name string
	Host string
}

type Discoverer interface {
	Discover(context.Context, string, Credentials, string, []string) ([]Instance, error)
}

type Client struct{ http *http.Client }

func NewClient() *Client {
	return &Client{http: &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Error only carries a known category, never an SDK error or a signed request.
type Error struct{ Code string }

func (e *Error) Error() string { return "cloud discovery: " + e.Code }

func apiError(err error) error {
	if errors.Is(err, context.Canceled) {
		return &Error{Code: "cancelled"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: "timeout"}
	}
	var api interface{ ErrorCode() string }
	if errors.As(err, &api) {
		return codeError(api.ErrorCode())
	}
	return &Error{Code: "api_request_failed"}
}

func codeError(code string) error {
	value := strings.ToLower(code)
	switch {
	case strings.Contains(value, "throttl"), strings.Contains(value, "ratelimit"), strings.Contains(value, "requestlimit"):
		return &Error{Code: "rate_limited"}
	case strings.Contains(value, "auth"), strings.Contains(value, "forbidden"), strings.Contains(value, "accesskey"), strings.Contains(value, "signature"), strings.Contains(value, "accessdenied"), strings.Contains(value, "token"):
		return &Error{Code: "credentials_or_permissions"}
	default:
		return &Error{Code: "api_request_failed"}
	}
}

func (c *Client) Discover(ctx context.Context, provider string, credentials Credentials, region string, ids []string) ([]Instance, error) {
	if !ValidProvider(provider) || !ValidRegion(region) || credentials.AccessKey == "" || credentials.SecretKey == "" || len(ids) > 100 {
		return nil, &Error{Code: "invalid_configuration"}
	}
	for _, value := range ids {
		if !ValidInstanceID(value) {
			return nil, &Error{Code: "invalid_configuration"}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, apiError(err)
	}
	var values []Instance
	var err error
	switch provider {
	case "aliyun":
		values, err = c.aliyun(ctx, credentials, region, ids)
	case "aws":
		values, err = c.aws(ctx, credentials, region, ids)
	case "huaweicloud":
		values, err = c.huawei(ctx, credentials, region)
	}
	if err != nil {
		return nil, err
	}
	if len(values) > MaxInstances {
		return nil, &Error{Code: "too_many_instances"}
	}
	if len(ids) == 0 {
		return values, nil
	}
	allowed := make(map[string]bool, len(ids))
	for _, value := range ids {
		allowed[value] = true
	}
	filtered := make([]Instance, 0, len(ids))
	for _, value := range values {
		if allowed[value.ID] {
			filtered = append(filtered, value)
		}
	}
	return filtered, nil
}

func nextPage(token string, seen map[string]bool) error {
	if token != "" && seen[token] {
		return &Error{Code: "incomplete_pagination"}
	}
	seen[token] = true
	return nil
}
