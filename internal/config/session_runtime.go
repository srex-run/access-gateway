package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"
)

func (c *Config) loadSessionRuntime() error {
	if c.GatewayRuntime != "local" && c.GatewayRuntime != "docker" && c.GatewayRuntime != "kubernetes" {
		return fmt.Errorf("GATEWAY_RUNTIME must be local, docker or kubernetes")
	}
	if c.GatewayRuntime == "local" {
		if c.SessionAgentControlPlaneURL == "" {
			host, port, err := net.SplitHostPort(c.HTTPAddr)
			if err != nil {
				return fmt.Errorf("local session runtime requires a valid HTTP_ADDR")
			}
			if host == "" || net.ParseIP(host).IsUnspecified() {
				host = "127.0.0.1"
			}
			c.SessionAgentControlPlaneURL = "http://" + net.JoinHostPort(host, port)
		}
	}
	if c.GatewayRuntime == "local" || c.GatewayRuntime == "docker" {
		if c.SessionAgentStateDirectory == "" {
			if c.GatewayRuntime == "docker" {
				return fmt.Errorf("Docker runtime requires SESSION_AGENT_STATE_DIR")
			}
			var err error
			c.SessionAgentStateDirectory, err = filepath.Abs("var/session-agents")
			if err != nil {
				return err
			}
		}
		if !filepath.IsAbs(c.SessionAgentStateDirectory) {
			return fmt.Errorf("SESSION_AGENT_STATE_DIR must be absolute")
		}
	}
	endpoint, _ := url.Parse(c.SessionAgentControlPlaneURL)
	allowLocalHTTP := c.GatewayRuntime == "local" && endpoint != nil && endpoint.Scheme == "http" && net.ParseIP(endpoint.Hostname()).IsLoopback()
	var err error
	if c.SessionAgentAllowAuditHTTP, err = envBool("SESSION_AGENT_ALLOW_AUDIT_HTTP", allowLocalHTTP); err != nil {
		return err
	}
	if c.SessionAgentStartupTimeout, err = envDuration("SESSION_AGENT_STARTUP_TIMEOUT", c.SessionAgentStartupTimeout); err != nil {
		return err
	}
	if c.SessionAgentMaxSessions, err = envInt("SESSION_AGENT_MAX_SESSIONS", c.SessionAgentMaxSessions); err != nil {
		return err
	}
	if c.SessionAgentPortStart, err = envInt("SESSION_AGENT_PORT_START", c.SessionAgentPortStart); err != nil {
		return err
	}
	if c.SessionAgentPortEnd, err = envInt("SESSION_AGENT_PORT_END", c.SessionAgentPortEnd); err != nil {
		return err
	}
	if c.SessionAgentPublicHost == "" || c.SessionAgentControlPlaneURL == "" || c.SessionAgentStartupTimeout < time.Second || c.SessionAgentStartupTimeout > 90*time.Second || c.SessionAgentMaxSessions < 1 || c.SessionAgentMaxSessions > 100000 {
		return fmt.Errorf("session runtime requires PUBLIC_URL, SESSION_AGENT_CONTROL_PLANE_URL and valid startup timeout/capacity")
	}
	if endpoint == nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && c.SessionAgentAllowAuditHTTP)) {
		return fmt.Errorf("SESSION_AGENT_CONTROL_PLANE_URL must use HTTPS unless HTTP is explicitly allowed")
	}
	if c.GatewayRuntime == "kubernetes" && (c.SessionAgentImage == "" || c.SessionAgentNodeName == "") {
		return fmt.Errorf("Kubernetes runtime requires SESSION_AGENT_IMAGE and SESSION_AGENT_NODE_NAME")
	}
	if c.GatewayRuntime == "docker" && (c.SessionAgentImage == "" || !filepath.IsAbs(c.SessionAgentDockerStateDirectory) || !filepath.IsAbs(c.SessionAgentDockerSocket)) {
		return fmt.Errorf("Docker runtime requires SESSION_AGENT_IMAGE, SESSION_AGENT_DOCKER_STATE_DIR and an absolute SESSION_AGENT_DOCKER_SOCKET")
	}
	if (c.GatewayRuntime == "local" || c.GatewayRuntime == "docker") && (net.ParseIP(c.SessionAgentBindHost) == nil || c.SessionAgentPortStart < 1024 || c.SessionAgentPortEnd > 65535 || c.SessionAgentPortEnd < c.SessionAgentPortStart || c.SessionAgentMaxSessions > c.SessionAgentPortEnd-c.SessionAgentPortStart+1) {
		return fmt.Errorf("invalid SESSION_AGENT_BIND_HOST or session port range/capacity")
	}
	return nil
}
