package sessionruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/sessionproxy"
)

const (
	managedLabel      = "app.kubernetes.io/managed-by"
	managedValue      = "access-gateway-session-controller"
	sessionLabel      = "access-gateway.srex.run/session-id"
	appLabel          = "app.kubernetes.io/name"
	appValue          = "session-agent"
	terminalRetention = 7 * 24 * time.Hour
)

type Options struct {
	AuditProfiles   sessionproxy.ProfileSource
	Namespace       string
	Image           string
	NodeName        string
	PublicAddress   string
	ControlPlaneURL string
	AllowAuditHTTP  bool
	StartupTimeout  time.Duration
	PollInterval    time.Duration
	MaxSessions     int
	Credentials     *gatewayauth.SessionCredentials
}

type Client struct {
	kube      kubernetes.Interface
	options   Options
	callAgent func(context.Context, *corev1.Pod, gatewayagent.SessionConfig, string, any) error
}

func sessionExpiry(started time.Time, request gateway.CreateSessionRequest) time.Time {
	if request.ExpiresAt != nil {
		return request.ExpiresAt.UTC()
	}
	return started.Add(time.Duration(request.TTLSeconds) * time.Second)
}

func NewClient(kube kubernetes.Interface, options Options) (*Client, error) {
	if kube == nil || options.Credentials == nil || len(validation.IsDNS1123Label(options.Namespace)) != 0 ||
		len(validation.IsDNS1123Subdomain(options.NodeName)) != 0 || strings.TrimSpace(options.Image) == "" || strings.ContainsAny(options.Image, " \t\r\n") {
		return nil, fmt.Errorf("session runtime requires a Kubernetes client, namespace, node, agent image, and audit signer")
	}
	if net.ParseIP(options.PublicAddress) == nil && len(validation.IsDNS1123Subdomain(options.PublicAddress)) != 0 {
		return nil, fmt.Errorf("session public address must be a hostname or IP without a port")
	}
	endpoint, err := url.Parse(options.ControlPlaneURL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.ForceQuery ||
		(endpoint.Scheme != "https" && !(options.AllowAuditHTTP && endpoint.Scheme == "http")) {
		return nil, fmt.Errorf("session audit control-plane URL must use HTTPS")
	}
	if options.StartupTimeout == 0 {
		options.StartupTimeout = 90 * time.Second
	}
	if options.PollInterval == 0 {
		options.PollInterval = 250 * time.Millisecond
	}
	if options.MaxSessions == 0 {
		options.MaxSessions = 100
	}
	if options.StartupTimeout < time.Second || options.StartupTimeout > 90*time.Second || options.PollInterval <= 0 || options.MaxSessions < 1 || options.MaxSessions > 100000 {
		return nil, fmt.Errorf("session runtime timeout or capacity is invalid")
	}
	c := &Client{kube: kube, options: options}
	c.callAgent = c.agentRequest
	return c, nil
}

func (c *Client) PublicHost() string  { return c.options.PublicAddress }
func (c *Client) RuntimeMode() string { return "kubernetes" }

func (c *Client) CreateSession(context.Context, string, gateway.CreateSessionRequest) (gateway.CreateSessionResponse, error) {
	return gateway.CreateSessionResponse{}, fmt.Errorf("Kubernetes sessions require an approved asset target")
}

func (c *Client) CreateApprovedSession(ctx context.Context, gatewayID string, request gateway.CreateSessionRequest, targetHost string) (gateway.CreateSessionResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.options.StartupTimeout)
	defer cancel()
	started := time.Now().UTC().Truncate(time.Second)
	if request.ExpiresAt != nil {
		started = time.Now().UTC()
	}
	cfg := gatewayagent.SessionConfig{
		Version: 1, GatewayID: gatewayID, Request: request, TargetHost: targetHost,
		StartedAt: started, ExpiresAt: sessionExpiry(started, request),
		ControlPlaneURL: c.options.ControlPlaneURL, AuditAllowHTTP: c.options.AllowAuditHTTP,
	}
	proxy, err := sessionproxy.ResolveProfile(ctx, c.options.AuditProfiles, request.AuditPolicy)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	cfg.Proxy = proxy
	if err := cfg.Validate(); err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	record, err := c.ensureRecord(ctx, cfg)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	if record.Data["state"] != "active" {
		return gateway.CreateSessionResponse{}, fmt.Errorf("session is already closed")
	}
	cfg.StartedAt, err = time.Parse(time.RFC3339Nano, record.Data["started_at"])
	if err != nil {
		return gateway.CreateSessionResponse{}, fmt.Errorf("invalid session start record: %w", err)
	}
	cfg.ExpiresAt, err = time.Parse(time.RFC3339Nano, record.Data["expires_at"])
	if err != nil || !cfg.ExpiresAt.After(time.Now()) {
		return gateway.CreateSessionResponse{}, fmt.Errorf("session grant has expired")
	}
	cfg, err = c.ensureSecret(ctx, record, cfg)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	if err := c.ensurePod(ctx, record); err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	var response gateway.CreateSessionResponse
	var readyPod *corev1.Pod
	err = c.poll(ctx, func() (bool, error) {
		if err := c.requireActive(ctx, record); err != nil {
			return false, err
		}
		pod, err := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("get session Pod readiness: %w", err)
		}
		if !owned(pod.ObjectMeta, record) {
			return false, fmt.Errorf("session Pod ownership changed")
		}
		if pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
			return false, fmt.Errorf("session agent stopped before becoming ready")
		}
		if !podReady(pod) {
			return false, nil
		}
		if err := c.callAgent(ctx, pod, cfg, "/status", &response); err != nil {
			return false, nil
		}
		if response.SessionID != request.SessionID || response.ConnectionMode != request.ConnectionMode || response.Status != "running" ||
			response.ListenerPort != gatewayagent.SessionListenerPort || !response.StartedAt.Equal(cfg.StartedAt) || !response.ExpiresAt.Equal(cfg.ExpiresAt) {
			return false, fmt.Errorf("session agent returned an inconsistent grant")
		}
		readyPod = pod
		return true, nil
	})
	if err != nil {
		return gateway.CreateSessionResponse{}, fmt.Errorf("wait for session agent: %w", err)
	}
	if cfg.Request.WebOnly {
		response.ProcessID = "pod:" + c.options.Namespace + ":" + record.Name
		return response, nil
	}
	service, err := c.ensureService(ctx, record)
	if err != nil {
		return gateway.CreateSessionResponse{}, err
	}
	err = c.poll(ctx, func() (bool, error) {
		if err := c.requireActive(ctx, record); err != nil {
			return false, err
		}
		return c.endpointsReady(ctx, service, readyPod)
	})
	if err != nil {
		return gateway.CreateSessionResponse{}, fmt.Errorf("wait for session Service endpoints: %w", err)
	}
	response.ExternalPort = int(service.Spec.Ports[0].NodePort)
	response.ExposureMode = "kubernetes_nodeport"
	response.ExposureRef = "kubernetes/service/" + c.options.Namespace + "/" + service.Name
	response.ProcessID = "pod:" + c.options.Namespace + ":" + record.Name
	return response, nil
}

func (c *Client) ensureRecord(ctx context.Context, cfg gatewayagent.SessionConfig) (*corev1.ConfigMap, error) {
	encoded, err := json.Marshal(struct {
		GatewayID string
		Request   gateway.CreateSessionRequest
		Target    string
	}{cfg.GatewayID, cfg.Request, cfg.TargetHost})
	if err != nil {
		return nil, fmt.Errorf("encode session grant fingerprint: %w", err)
	}
	sum := sha256.Sum256(encoded)
	clear(encoded)
	fingerprint := hex.EncodeToString(sum[:])
	records := c.kube.CoreV1().ConfigMaps(c.options.Namespace)
	name := resourceName(cfg.Request.SessionID)
	record, err := records.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		record, err = records.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels(cfg.Request.SessionID)},
			Data: map[string]string{"state": "active", "fingerprint": fingerprint, "gateway_id": cfg.GatewayID,
				"connection_mode": cfg.Request.ConnectionMode,
				"started_at":      cfg.StartedAt.Format(time.RFC3339Nano), "expires_at": cfg.ExpiresAt.Format(time.RFC3339Nano)},
		}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			record, err = records.Get(ctx, name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return nil, fmt.Errorf("create session lifecycle record: %w", err)
	}
	if !managed(record.ObjectMeta, cfg.Request.SessionID) || record.Data["state"] != "active" || record.Data["fingerprint"] != fingerprint || record.UID == "" {
		return nil, fmt.Errorf("session is closed or conflicts with an existing grant")
	}
	return record, nil
}

func (c *Client) ensureSecret(ctx context.Context, record *corev1.ConfigMap, cfg gatewayagent.SessionConfig) (gatewayagent.SessionConfig, error) {
	secrets := c.kube.CoreV1().Secrets(c.options.Namespace)
	secret, err := secrets.Get(ctx, record.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		cfg.Certificate, cfg.PrivateKey, err = gatewayagent.NewSessionIdentity(cfg.ExpiresAt)
		if err != nil {
			return gatewayagent.SessionConfig{}, err
		}
		cfg.AuditToken = c.options.Credentials.Issue(cfg.GatewayID, cfg.Request.SessionID, cfg.ExpiresAt.Add(10*time.Minute))
		encoded, err := json.Marshal(cfg)
		if err != nil {
			return gatewayagent.SessionConfig{}, fmt.Errorf("encode session Secret: %w", err)
		}
		defer clear(encoded)
		secret, err = secrets.Create(ctx, &corev1.Secret{ObjectMeta: resourceMeta(record), Immutable: ptr(true),
			Data: map[string][]byte{"session.json": encoded}}, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			secret, err = secrets.Get(ctx, record.Name, metav1.GetOptions{})
		}
		if err != nil {
			return gatewayagent.SessionConfig{}, fmt.Errorf("create session Secret: %w", err)
		}
	}
	if err != nil {
		return gatewayagent.SessionConfig{}, fmt.Errorf("get session Secret: %w", err)
	}
	if !owned(secret.ObjectMeta, record) || secret.Immutable == nil || !*secret.Immutable {
		return gatewayagent.SessionConfig{}, fmt.Errorf("session Secret ownership changed")
	}
	existing, err := gatewayagent.DecodeSessionConfig(secret.Data["session.json"])
	if err != nil {
		return gatewayagent.SessionConfig{}, err
	}
	if existing.GatewayID != cfg.GatewayID || !gateway.SameCreateRequest(existing.Request, cfg.Request) || existing.TargetHost != cfg.TargetHost ||
		!existing.StartedAt.Equal(cfg.StartedAt) || !existing.ExpiresAt.Equal(cfg.ExpiresAt) {
		return gatewayagent.SessionConfig{}, fmt.Errorf("session Secret does not match the approved grant")
	}
	return existing, nil
}

func (c *Client) requireActive(ctx context.Context, record *corev1.ConfigMap) error {
	current, err := c.kube.CoreV1().ConfigMaps(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("check session grant: %w", err)
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, current.Data["expires_at"])
	if current.UID != record.UID || current.Data["state"] != "active" || parseErr != nil || !expires.After(time.Now()) {
		return fmt.Errorf("session grant is revoked or expired")
	}
	return nil
}

func (c *Client) CloseSession(ctx context.Context, _ string, sessionID, _ string) (gateway.CloseSessionResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.CloseSessionResponse{}, fmt.Errorf("invalid session ID")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	record, err := c.closeRecord(ctx, sessionID)
	if err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	if err := c.cleanup(ctx, record); err != nil {
		return gateway.CloseSessionResponse{}, err
	}
	status := "closed"
	if expiry, err := time.Parse(time.RFC3339Nano, record.Data["expires_at"]); err == nil && !expiry.After(time.Now()) {
		status = "expired"
	}
	return gateway.CloseSessionResponse{SessionID: sessionID, Status: status, ClosedAt: time.Now()}, nil
}

func (c *Client) closeRecord(ctx context.Context, sessionID string) (*corev1.ConfigMap, error) {
	records := c.kube.CoreV1().ConfigMaps(c.options.Namespace)
	var record *corev1.ConfigMap
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var err error
		record, err = records.Get(ctx, resourceName(sessionID), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			record, err = records.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: resourceName(sessionID), Labels: labels(sessionID)},
				Data: map[string]string{"state": "closed", "closed_at": time.Now().UTC().Format(time.RFC3339Nano)}}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				return apierrors.NewConflict(corev1.Resource("configmaps"), resourceName(sessionID), err)
			}
			return err
		}
		if err != nil {
			return err
		}
		if !managed(record.ObjectMeta, sessionID) {
			return fmt.Errorf("refuse to close an unowned session record")
		}
		if record.Data["state"] == "closed" {
			return nil
		}
		if record.Data == nil {
			record.Data = make(map[string]string)
		}
		record.Data["state"], record.Data["closed_at"] = "closed", time.Now().UTC().Format(time.RFC3339Nano)
		record, err = records.Update(ctx, record, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("persist session revocation: %w", err)
	}
	return record, nil
}

func (c *Client) cleanup(ctx context.Context, record *corev1.ConfigMap) error {
	services, pods, secrets := c.kube.CoreV1().Services(c.options.Namespace), c.kube.CoreV1().Pods(c.options.Namespace), c.kube.CoreV1().Secrets(c.options.Namespace)
	service, err := services.Get(ctx, record.Name, metav1.GetOptions{})
	if err == nil {
		if !owned(service.ObjectMeta, record) {
			return fmt.Errorf("refuse to delete an unowned session Service")
		}
		err = services.Delete(ctx, service.Name, deleteOptions(service.UID))
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete session Service: %w", err)
	}
	pod, err := pods.Get(ctx, record.Name, metav1.GetOptions{})
	if err == nil {
		if !owned(pod.ObjectMeta, record) {
			return fmt.Errorf("refuse to delete an unowned session Pod")
		}
		if pod.Status.Phase == corev1.PodRunning && pod.DeletionTimestamp == nil {
			secret, getErr := secrets.Get(ctx, record.Name, metav1.GetOptions{})
			if getErr != nil {
				return fmt.Errorf("load session management identity for revocation: %w", getErr)
			}
			if !owned(secret.ObjectMeta, record) {
				return fmt.Errorf("session management identity is not owned")
			}
			cfg, decodeErr := gatewayagent.DecodeSessionConfig(secret.Data["session.json"])
			if decodeErr != nil {
				return decodeErr
			}
			var response gateway.CloseSessionResponse
			if stopErr := c.callAgent(ctx, pod, cfg, "/stop", &response); stopErr != nil {
				return fmt.Errorf("stop session agent and flush audit: %w", stopErr)
			}
			if response.SessionID != record.Labels[sessionLabel] || response.Status != "closed" {
				return fmt.Errorf("invalid session stop acknowledgement")
			}
		}
		if err := pods.Delete(ctx, pod.Name, deleteOptions(pod.UID)); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete session Pod: %w", err)
		}
		if err := c.poll(ctx, func() (bool, error) {
			_, err := pods.Get(ctx, record.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		}); err != nil {
			return fmt.Errorf("wait for session Pod termination: %w", err)
		}
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get session Pod for revocation: %w", err)
	}
	secret, err := secrets.Get(ctx, record.Name, metav1.GetOptions{})
	if err == nil {
		if !owned(secret.ObjectMeta, record) {
			return fmt.Errorf("refuse to delete an unowned session Secret")
		}
		err = secrets.Delete(ctx, secret.Name, deleteOptions(secret.UID))
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete session Secret: %w", err)
	}
	return nil
}

func (c *Client) GetSession(ctx context.Context, _ string, sessionID string) (gateway.SessionStatusResponse, error) {
	if !id.IsUUID(sessionID) {
		return gateway.SessionStatusResponse{}, fmt.Errorf("invalid session ID")
	}
	response := gateway.SessionStatusResponse{SessionID: sessionID, ConnectionMode: gateway.ConnectionModeNative, Status: "not_found"}
	record, err := c.kube.CoreV1().ConfigMaps(c.options.Namespace).Get(ctx, resourceName(sessionID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return response, nil
	}
	if err != nil {
		return response, fmt.Errorf("get session lifecycle record: %w", err)
	}
	if !managed(record.ObjectMeta, sessionID) {
		return response, fmt.Errorf("session lifecycle record is unowned")
	}
	response.Status = "starting"
	if mode := record.Data["connection_mode"]; mode != "" {
		response.ConnectionMode = mode
	}
	expires, _ := time.Parse(time.RFC3339Nano, record.Data["expires_at"])
	response.ExpiresAt = &expires
	if record.Data["state"] == "closed" {
		response.Status = "stopping"
		_, podErr := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
		_, serviceErr := c.kube.CoreV1().Services(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(podErr) && apierrors.IsNotFound(serviceErr) {
			response.Status = "closed"
			if !expires.IsZero() && !expires.After(time.Now()) {
				response.Status = "expired"
			}
		}
		return response, nil
	}
	pod, err := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return response, nil
	}
	if err != nil {
		return response, fmt.Errorf("get session Pod status: %w", err)
	}
	if !owned(pod.ObjectMeta, record) {
		return response, fmt.Errorf("session Pod is unowned")
	}
	if podReady(pod) && expires.After(time.Now()) {
		response.Status = "running"
	}
	return response, nil
}

func (c *Client) CheckReady(ctx context.Context, endpoint string) error {
	_, err := c.GetReadiness(ctx, endpoint)
	return err
}

func (c *Client) GetReadiness(ctx context.Context, _ string) (gateway.ReadinessReport, error) {
	_, err := c.kube.CoreV1().Pods(c.options.Namespace).List(ctx, metav1.ListOptions{LabelSelector: managedLabel + "=" + managedValue, Limit: 1})
	if err != nil {
		return gateway.ReadinessReport{}, fmt.Errorf("session Kubernetes API is unavailable: %w", err)
	}
	return gateway.ReadinessReport{Status: "ready", MaxSessions: ptr(c.options.MaxSessions)}, nil
}

// Reconcile runs on every control-plane replica. Named records, conditional
// updates, and UID-guarded deletes make cleanup safe to retry after a rollout.
func (c *Client) Reconcile(ctx context.Context) ([]string, error) {
	var ended []string
	var failures []error
	continuation := ""
	for {
		records, err := c.kube.CoreV1().ConfigMaps(c.options.Namespace).List(ctx, metav1.ListOptions{LabelSelector: managedLabel + "=" + managedValue, Limit: 100, Continue: continuation})
		if err != nil {
			return ended, fmt.Errorf("list session lifecycle records: %w", err)
		}
		for _, record := range records.Items {
			sessionID := record.Labels[sessionLabel]
			if !id.IsUUID(sessionID) || record.Name != resourceName(sessionID) {
				continue
			}
			closed, closedErr := time.Parse(time.RFC3339Nano, record.Data["closed_at"])
			if record.Data["state"] == "closed" && record.Data["acknowledged"] == "true" && record.Data["drained"] == "true" && closedErr == nil {
				if time.Since(closed) > terminalRetention {
					if err := c.kube.CoreV1().ConfigMaps(c.options.Namespace).Delete(ctx, record.Name, deleteOptions(record.UID)); err != nil && !apierrors.IsNotFound(err) {
						failures = append(failures, fmt.Errorf("prune acknowledged session record: %w", err))
					}
				}
				continue
			}
			expires, parseErr := time.Parse(time.RFC3339Nano, record.Data["expires_at"])
			stop := record.Data["state"] == "closed" || parseErr != nil || !expires.After(time.Now())
			if !stop {
				pod, err := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
				started, _ := time.Parse(time.RFC3339Nano, record.Data["started_at"])
				if apierrors.IsNotFound(err) {
					stop = time.Since(started) > c.options.StartupTimeout+30*time.Second
				} else if err != nil {
					failures = append(failures, fmt.Errorf("inspect session Pod: %w", err))
					continue
				} else {
					stop = pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed ||
						!podReady(pod) && time.Since(started) > c.options.StartupTimeout+30*time.Second
					if !stop && time.Since(started) > c.options.StartupTimeout+30*time.Second {
						_, serviceErr := c.kube.CoreV1().Services(c.options.Namespace).Get(ctx, record.Name, metav1.GetOptions{})
						if apierrors.IsNotFound(serviceErr) {
							stop = true
						} else if serviceErr != nil {
							failures = append(failures, fmt.Errorf("inspect session Service: %w", serviceErr))
							continue
						}
					}
				}
			}
			if !stop {
				continue
			}
			if record.Data["acknowledged"] != "true" {
				ended = append(ended, sessionID)
			}
			if _, err := c.CloseSession(ctx, "", sessionID, "reconcile"); err != nil {
				failures = append(failures, fmt.Errorf("reconcile session %s: %w", sessionID, err))
				continue
			}
			if record.Data["acknowledged"] == "true" {
				if err := c.AcknowledgeClosure(ctx, sessionID); err != nil {
					failures = append(failures, err)
				}
			}
		}
		if records.Continue == "" {
			break
		}
		continuation = records.Continue
	}
	return ended, errors.Join(failures...)
}

func (c *Client) AcknowledgeClosure(ctx context.Context, sessionID string) error {
	if !id.IsUUID(sessionID) {
		return fmt.Errorf("invalid session ID")
	}
	name := resourceName(sessionID)
	_, podErr := c.kube.CoreV1().Pods(c.options.Namespace).Get(ctx, name, metav1.GetOptions{})
	_, serviceErr := c.kube.CoreV1().Services(c.options.Namespace).Get(ctx, name, metav1.GetOptions{})
	_, secretErr := c.kube.CoreV1().Secrets(c.options.Namespace).Get(ctx, name, metav1.GetOptions{})
	if !apierrors.IsNotFound(podErr) || !apierrors.IsNotFound(serviceErr) || !apierrors.IsNotFound(secretErr) {
		return fmt.Errorf("session resource cleanup is not confirmed")
	}
	records := c.kube.CoreV1().ConfigMaps(c.options.Namespace)
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		record, err := records.Get(ctx, resourceName(sessionID), metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !managed(record.ObjectMeta, sessionID) || record.Data["state"] != "closed" {
			return fmt.Errorf("session closure is not owned or complete")
		}
		closed, err := time.Parse(time.RFC3339Nano, record.Data["closed_at"])
		if err != nil {
			return fmt.Errorf("invalid session closure time: %w", err)
		}
		drained := time.Since(closed) > c.options.StartupTimeout+30*time.Second
		if record.Data["acknowledged"] == "true" && (!drained || record.Data["drained"] == "true") {
			return nil
		}
		record.Data["acknowledged"] = "true"
		if drained {
			record.Data["drained"] = "true"
		}
		_, err = records.Update(ctx, record, metav1.UpdateOptions{})
		return err
	})
	if err != nil {
		return fmt.Errorf("acknowledge session closure: %w", err)
	}
	return nil
}

func (c *Client) agentRequest(ctx context.Context, pod *corev1.Pod, cfg gatewayagent.SessionConfig, path string, result any) error {
	if net.ParseIP(pod.Status.PodIP) == nil {
		return fmt.Errorf("session Pod has no management address")
	}
	return requestSessionAgent(ctx, net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(gatewayagent.SessionManagementPort)), cfg, path, result)
}

func requestSessionAgent(ctx context.Context, address string, cfg gatewayagent.SessionConfig, path string, result any) error {
	tlsConfig, err := cfg.ManagementTLS(false)
	if err != nil {
		return err
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	timeout := 3 * time.Second
	method := http.MethodGet
	if path == "/stop" {
		method = http.MethodPost
		timeout = 25 * time.Second
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+address+path, nil)
	if err != nil {
		return fmt.Errorf("build session management request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("session management connection failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("session management returned HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(result); err != nil {
		return fmt.Errorf("decode session management response: %w", err)
	}
	return nil
}

func (c *Client) poll(ctx context.Context, check func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := check()
		if err != nil || done {
			return err
		}
		timer := time.NewTimer(c.options.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func resourceName(sessionID string) string { return "session-" + sessionID }
func labels(sessionID string) map[string]string {
	return map[string]string{managedLabel: managedValue, sessionLabel: sessionID, appLabel: appValue}
}
func ptr[T any](value T) *T { return &value }
func deleteOptions(uid types.UID) metav1.DeleteOptions {
	return metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}
}
func managed(meta metav1.ObjectMeta, sessionID string) bool {
	return meta.Name == resourceName(sessionID) && meta.Labels[managedLabel] == managedValue && meta.Labels[sessionLabel] == sessionID
}
func resourceMeta(record *corev1.ConfigMap) metav1.ObjectMeta {
	return metav1.ObjectMeta{Name: record.Name, Labels: labels(record.Labels[sessionLabel]), OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: record.Name, UID: record.UID, Controller: ptr(true)}}}
}
func owned(meta metav1.ObjectMeta, record *corev1.ConfigMap) bool {
	return managed(meta, record.Labels[sessionLabel]) && reflect.DeepEqual(meta.OwnerReferences, resourceMeta(record).OwnerReferences)
}
func podReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning || pod.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
