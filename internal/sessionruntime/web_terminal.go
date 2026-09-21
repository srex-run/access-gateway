package sessionruntime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/terminal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func dialTerminal(ctx context.Context, address string, cfg gatewayagent.SessionConfig, sourceIP string) (*websocket.Conn, error) {
	if !cfg.ExpiresAt.After(time.Now()) || cfg.Proxy == nil || !terminal.Supported(cfg.Proxy.Protocol) || net.ParseIP(sourceIP) == nil {
		return nil, fmt.Errorf("terminal unavailable")
	}
	tlsConfig, err := cfg.ManagementTLS(false)
	if err != nil {
		return nil, err
	}
	dialer := websocket.Dialer{TLSClientConfig: tlsConfig, HandshakeTimeout: 5 * time.Second}
	conn, response, err := dialer.DialContext(ctx, "wss://"+address+"/terminal", http.Header{"X-Terminal-Source-Ip": []string{sourceIP}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("session terminal unavailable")
	}
	return conn, nil
}

func (c *HostClient) OpenTerminal(ctx context.Context, sessionID, sourceIP string) (*websocket.Conn, error) {
	record, ok, err := c.snapshot(sessionID)
	if err != nil {
		return nil, err
	}
	if !ok || record.State != "running" || !record.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("session terminal unavailable")
	}
	resource, err := c.driver.Inspect(ctx, record)
	if err != nil || !resource.Running {
		return nil, fmt.Errorf("session worker unavailable")
	}
	cfg, err := c.loadGrant(record)
	if err != nil {
		return nil, err
	}
	return dialTerminal(ctx, cfg.ManagementAddress(), cfg, sourceIP)
}

func (c *Client) OpenTerminal(ctx context.Context, sessionID, sourceIP string) (*websocket.Conn, error) {
	if !id.IsUUID(sessionID) {
		return nil, fmt.Errorf("invalid session ID")
	}
	record, err := c.kube.CoreV1().ConfigMaps(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if !managed(record.ObjectMeta, sessionID) {
		return nil, fmt.Errorf("session record is unowned")
	}
	if err = c.requireActive(ctx, record); err != nil {
		return nil, err
	}
	pod, err := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if !owned(pod.ObjectMeta, record) || !podReady(pod) || string(pod.UID) != record.Data["pod_uid"] || net.ParseIP(pod.Status.PodIP) == nil {
		return nil, fmt.Errorf("session worker unavailable")
	}
	secret, err := c.kube.CoreV1().Secrets(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if !owned(secret.ObjectMeta, record) || secret.Immutable == nil || !*secret.Immutable {
		return nil, fmt.Errorf("session grant is unowned")
	}
	cfg, err := gatewayagent.DecodeSessionConfig(secret.Data["session.json"])
	if err != nil {
		return nil, err
	}
	if cfg.Request.SessionID != sessionID || cfg.GatewayID != record.Data["gateway_id"] {
		return nil, fmt.Errorf("session grant mismatch")
	}
	return dialTerminal(ctx, net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(gatewayagent.SessionManagementPort)), cfg, sourceIP)
}
