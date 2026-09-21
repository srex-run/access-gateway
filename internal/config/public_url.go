package config

import (
	"fmt"
	"net"

	"github.com/srex-run/access-gateway/internal/publicurl"
)

// The browser origin and session gateway identity have one deployment-owned source.
// The control-plane callback URL remains separate for container/private networks.
func (c *Config) loadPublicURL() error {
	if c.PublicURL == "" {
		if c.GatewayRuntime == "docker" || c.GatewayRuntime == "kubernetes" {
			return fmt.Errorf("PUBLIC_URL is required for the %s session runtime", c.GatewayRuntime)
		}
		_, port, err := net.SplitHostPort(c.HTTPAddr)
		if err != nil {
			return fmt.Errorf("HTTP_ADDR must include a port when PUBLIC_URL is unset")
		}
		c.PublicURL = "http://" + net.JoinHostPort("127.0.0.1", port)
	}
	endpoint, err := publicurl.Parse(c.PublicURL)
	if err != nil {
		return err
	}
	c.PublicURL = endpoint.String()
	c.SessionAgentPublicHost = endpoint.Hostname()
	return nil
}
