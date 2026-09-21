package publicurl

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Parse validates the deployment-owned browser origin. Paths, credentials and
// wildcard hosts are not valid public platform addresses.
func Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimRight(raw, "/")
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Hostname() == "" || strings.HasSuffix(endpoint.Host, ":") || endpoint.User != nil || endpoint.Opaque != "" ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" ||
		strings.Contains(raw, "#") || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, fmt.Errorf("PUBLIC_URL must be an HTTP or HTTPS origin without credentials, path, query or fragment")
	}
	if port := endpoint.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("PUBLIC_URL port must be between 1 and 65535")
		}
	}
	host := endpoint.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return nil, fmt.Errorf("PUBLIC_URL must use a reachable host, not a wildcard address")
		}
	} else {
		if len(host) > 253 {
			return nil, fmt.Errorf("PUBLIC_URL hostname is too long")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("PUBLIC_URL hostname is invalid")
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return nil, fmt.Errorf("PUBLIC_URL hostname is invalid")
				}
			}
		}
	}
	endpoint.Host = strings.ToLower(endpoint.Host)
	return endpoint, nil
}
