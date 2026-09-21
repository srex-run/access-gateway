//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/approvalflow"
	"github.com/srex-run/access-gateway/internal/config"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayagent"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/httpapi"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/observability"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
	"github.com/srex-run/access-gateway/internal/security"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
	"github.com/srex-run/access-gateway/internal/worker"
)

const (
	httpFlowGatewaySecret   = "gateway-internal-secret-32-bytes-minimum"
	httpFlowCollectorSecret = "audit-collector-secret-32-bytes-minimum"
	httpFlowCallbackSecret  = "feishu-callback-secret-32-bytes-minimum"
	httpFlowMetricsToken    = "metrics-bearer-token-32-bytes-minimum"
	httpFlowTarget          = "10.40.0.25"
	httpFlowSourceIP        = "203.0.113.25"
	httpFlowTargetAccount   = "readonly"
)

func TestHTTPMainFlowThroughWorkerAndGatewayAgent(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin := createHTTPFlowUser(t, ctx, repos, database, "ou-http-admin", "HTTP Admin")
	approver := createHTTPFlowUser(t, ctx, repos, database, "ou-http-approver", "HTTP Approver")

	feishuPlatform := newFakeFeishuPlatform()
	originalTransport := http.DefaultTransport
	http.DefaultTransport = &httpFlowFeishuTransport{platform: feishuPlatform, fallback: originalTransport}
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	gatewayProxyHandler := &switchableHTTPHandler{}
	gatewayProxy := httptest.NewServer(gatewayProxyHandler)
	t.Cleanup(gatewayProxy.Close)

	keyPath := filepath.Join(t.TempDir(), "asset-encryption-key")
	if err := os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write asset encryption key: %v", err)
	}

	controlPlane := httptest.NewUnstartedServer(nil)
	t.Cleanup(controlPlane.Close)
	cfg := config.Config{
		PublicURL:                     "http://" + controlPlane.Listener.Addr().String(),
		SessionDefaultTTL:             2 * time.Minute,
		SessionMaxTTL:                 5 * time.Minute,
		ApprovalTimeout:               time.Hour,
		AllowDevAuth:                  true,
		GatewayHealthInterval:         25 * time.Millisecond,
		GatewayHeartbeatMaxAge:        2 * time.Second,
		GatewayHealthFailureThreshold: 2,
		AuditCollectorSecret:          httpFlowCollectorSecret,
		EncryptionKey:                 "http-flow-encryption-key-32-bytes-minimum",
		AssetEncryptionKeyFile:        keyPath,
		AssetEncryptionKeyID:          "http-flow-key-v1",
		AdminUserIDs:                  map[string]struct{}{admin.ID: {}},
		MetricsEnabled:                true,
		MetricsBearerToken:            httpFlowMetricsToken,
	}
	gatewayClient, err := gateway.NewHTTPClientWithConfig(gateway.HTTPClientConfig{
		Timeout: time.Second, InternalSecret: httpFlowGatewaySecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeClient := &httpFlowSessionRuntime{HTTPClient: gatewayClient, endpoint: gatewayProxy.URL}
	components := newHTTPFlowComponents(t, ctx, database, cfg, runtimeClient)

	settingsConfig := settings.Defaults()
	settingsConfig.ClientAccessEnabled, settingsConfig.ClientAccessHost = true, "gateway.test"
	settingsConfig.Feishu = settings.FeishuConfig{AppID: "http-flow-app", TenantKey: "tenant-http-flow", LoginEnabled: true, NotificationsEnabled: true, CallbacksEnabled: true}
	view, err := components.HTTP.Settings.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	appSecret, callbackSecret := "http-flow-app-secret", httpFlowCallbackSecret
	if _, err := components.HTTP.Settings.Save(ctx, admin.ID, service.SettingsUpdate{Config: &settingsConfig, Revision: &view.Revision,
		Secrets: settings.SecretChanges{FeishuApp: &appSecret, FeishuCallback: &callbackSecret}}); err != nil {
		t.Fatal(err)
	}
	components.HTTP.FrontendRedirect = "/console"
	controlPlane.Config.Handler = components.HTTP.Container()
	controlPlane.Start()
	secondComponents := newHTTPFlowComponents(t, ctx, database, cfg, runtimeClient)
	secondComponents.HTTP.FrontendRedirect = "/console"
	secondControlPlane := httptest.NewServer(secondComponents.HTTP.Container())
	t.Cleanup(secondControlPlane.Close)
	plainClient := &http.Client{Timeout: 2 * time.Second}

	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/healthz", "", nil, nil), http.StatusOK)
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/readyz", "", nil, nil), http.StatusOK)
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/regions", "", nil, nil), http.StatusUnauthorized)
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/metrics", "", nil, nil), http.StatusUnauthorized)
	metrics := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/metrics", "", nil, map[string]string{"Authorization": "Bearer " + httpFlowMetricsToken})
	assertHTTPStatus(t, metrics, http.StatusOK)
	if !bytes.Contains(metrics.body, []byte("access_gateway_http_requests_total")) {
		t.Fatalf("metrics response does not contain HTTP metrics: %s", metrics.body)
	}

	applicantClient := newNoRedirectClient(t)
	login := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/auth/feishu/login", "", nil, nil)
	assertHTTPStatus(t, login, http.StatusFound)
	authorizationURL, err := url.Parse(login.header.Get("Location"))
	if err != nil {
		t.Fatalf("parse OAuth authorization URL: %v", err)
	}
	state := authorizationURL.Query().Get("state")
	if state == "" || authorizationURL.Query().Get("app_id") != "http-flow-app" || authorizationURL.Query().Get("app_secret") != "" {
		t.Fatalf("unexpected OAuth authorization URL: %s", authorizationURL)
	}
	callback := performHTTPRequest(t, applicantClient, http.MethodGet, secondControlPlane.URL+"/api/v1/auth/feishu/callback?code=http-flow-code&state="+url.QueryEscape(state), "", nil, nil)
	assertHTTPStatus(t, callback, http.StatusFound)
	if callback.header.Get("Location") != "/console" {
		t.Fatalf("OAuth callback redirect = %q", callback.header.Get("Location"))
	}
	applicant, err := repos.users.GetByFeishuOpenID(ctx, database, "ou-http-applicant")
	if err != nil || applicant.Status != domain.UserStatusActive {
		t.Fatalf("OAuth applicant = %+v err=%v", applicant, err)
	}
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/regions", "", nil, nil), http.StatusOK)

	regionResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/regions", admin.ID, map[string]any{
		"code": "http-flow-region", "name": "HTTP Flow Region", "status": "enabled",
	}, nil)
	assertHTTPStatus(t, regionResult, http.StatusCreated)
	region := decodeHTTPFlowResponse[httpFlowRegion](t, regionResult.body)

	gatewayResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/gateways", admin.ID, map[string]any{
		"region_id": region.ID, "name": "HTTP Flow Gateway", "management_endpoint": gatewayProxy.URL,
		"public_endpoint": "gateway.http-flow.internal:443", "status": "enabled", "max_sessions": 10,
	}, nil)
	assertHTTPStatus(t, gatewayResult, http.StatusCreated)
	gatewayRecord := decodeHTTPFlowResponse[httpFlowGateway](t, gatewayResult.body)

	workflowResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/workflows", admin.ID, approvalflow.Definition{
		Name: "HTTP Flow Approval", Enabled: true, TimeoutSeconds: 600,
		Steps: []approvalflow.Step{{Name: "Technical owner", Kind: "role_selector", Mode: "any", Selector: "access-gateway.io/role=http-approver"}},
	}, nil)
	assertHTTPStatus(t, workflowResult, http.StatusOK)
	workflow := decodeHTTPFlowResponse[approvalflow.Definition](t, workflowResult.body)

	assetResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/assets", admin.ID, map[string]any{
		"region_id": region.ID, "gateway_id": gatewayRecord.ID, "name": "HTTP Flow Database", "asset_type": "postgres",
		"target": httpFlowTarget, "risk_level": "sensitive", "max_ttl_seconds": 300, "status": "enabled",
		"approval_workflow_id": workflow.ID,
	}, nil)
	assertHTTPStatus(t, assetResult, http.StatusCreated)
	asset := decodeHTTPFlowResponse[httpFlowAsset](t, assetResult.body)
	if bytes.Contains(assetResult.body, []byte(httpFlowTarget)) || bytes.Contains(assetResult.body, []byte("target_ciphertext")) {
		t.Fatalf("asset response leaked target material: %s", assetResult.body)
	}
	storedAsset, err := repos.assets.GetByID(ctx, database, asset.ID)
	if err != nil || !strings.HasPrefix(storedAsset.TargetCiphertext, "agk1.") || strings.Contains(storedAsset.TargetCiphertext, httpFlowTarget) {
		t.Fatalf("stored encrypted asset = %+v err=%v", storedAsset, err)
	}

	catalog, err := gatewayagent.NewAssetCatalog([]gatewayagent.AssetCatalogEntry{{TargetID: asset.ID, Ports: []int{5432}}})
	if err != nil {
		t.Fatalf("create Gateway Agent catalog: %v", err)
	}
	controller := &lifecycleController{}
	manager, err := gatewayagent.NewManager(controller, &memoryStateStore{}, catalog, 5*time.Minute, zerolog.Nop())
	if err != nil {
		t.Fatalf("create Gateway Agent manager: %v", err)
	}
	if err := manager.Recover(ctx); err != nil {
		t.Fatalf("recover Gateway Agent state: %v", err)
	}
	agent, err := gatewayagent.NewServer(manager, httpFlowGatewaySecret, zerolog.Nop())
	if err != nil {
		t.Fatalf("create Gateway Agent server: %v", err)
	}
	gatewayProxyHandler.Set(agent.Container())

	portResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/assets/"+asset.ID+"/ports", admin.ID, map[string]any{
		"port": 5432, "protocol": "tcp",
	}, nil)
	assertHTTPStatus(t, portResult, http.StatusCreated)
	roleResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/roles", admin.ID, map[string]any{
		"name": "http-approver", "enabled": true, "permissions": []string{"approval:manage"},
	}, nil)
	assertHTTPStatus(t, roleResult, http.StatusOK)
	grantResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/admin/role-assignments", admin.ID, map[string]any{
		"user_id": approver.ID, "role": "http-approver",
	}, nil)
	assertHTTPStatus(t, grantResult, http.StatusCreated)
	catalogResult := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/admin/gateways/"+gatewayRecord.ID+"/catalog", admin.ID, nil, nil)
	assertHTTPStatus(t, catalogResult, http.StatusOK)
	exportedCatalog := decodeHTTPFlowResponse[httpFlowCatalog](t, catalogResult.body)
	if exportedCatalog.Version != 1 || exportedCatalog.GatewayID != gatewayRecord.ID || len(exportedCatalog.Assets) != 1 || exportedCatalog.Assets[0].TargetID != asset.ID || len(exportedCatalog.Assets[0].Ports) != 1 || exportedCatalog.Assets[0].Ports[0] != 5432 {
		t.Fatalf("exported Gateway Agent catalog = %+v", exportedCatalog)
	}
	if bytes.Contains(catalogResult.body, []byte(httpFlowTarget)) || bytes.Contains(catalogResult.body, []byte("ciphertext")) {
		t.Fatalf("gateway catalog leaked target material: %s", catalogResult.body)
	}

	workerCtx, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan error, 1)
	go func() { workerDone <- components.Worker.Run(workerCtx) }()
	t.Cleanup(func() {
		stopWorker()
		select {
		case workerErr := <-workerDone:
			if !errors.Is(workerErr, context.Canceled) {
				t.Errorf("worker stopped with %v", workerErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("worker did not stop after cancellation")
		}
	})

	waitForHTTPFlow(t, 3*time.Second, "gateway heartbeat", func() bool {
		current, getErr := repos.gateways.GetByID(ctx, database, gatewayRecord.ID)
		return getErr == nil && current.LastHeartbeatAt != nil && current.MaxSessions == 100
	})

	regionsResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/regions", "", nil, nil)
	assertHTTPStatus(t, regionsResult, http.StatusOK)
	assetsResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/regions/"+region.ID+"/assets", "", nil, nil)
	assertHTTPStatus(t, assetsResult, http.StatusOK)
	if bytes.Contains(assetsResult.body, []byte(httpFlowTarget)) || bytes.Contains(assetsResult.body, []byte("agk1.")) {
		t.Fatalf("directory response leaked target material: %s", assetsResult.body)
	}
	portsResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/assets/"+asset.ID+"/ports", "", nil, nil)
	assertHTTPStatus(t, portsResult, http.StatusOK)

	approvedRequestBody := map[string]any{
		"region_id": region.ID, "asset_id": asset.ID, "target_port": 5432,
		"source_ip": httpFlowSourceIP, "target_account": httpFlowTargetAccount,
		"reason": "validate the complete HTTP approval flow", "ttl_seconds": 120,
	}
	approvedRequestResult := performJSONRequest(t, applicantClient, http.MethodPost, controlPlane.URL+"/api/v1/access-requests", "", approvedRequestBody, map[string]string{"Idempotency-Key": "http-flow-approved"})
	assertHTTPStatus(t, approvedRequestResult, http.StatusCreated)
	approvedRequest := decodeHTTPFlowResponse[httpFlowAccessRequest](t, approvedRequestResult.body)
	if approvedRequest.Status != string(domain.AccessRequestPendingApproval) || approvedRequest.SourceIP != httpFlowSourceIP || approvedRequest.TargetAccount != httpFlowTargetAccount {
		t.Fatalf("new access request = %+v", approvedRequest)
	}
	replayedRequestResult := performJSONRequest(t, applicantClient, http.MethodPost, controlPlane.URL+"/api/v1/access-requests", "", approvedRequestBody, map[string]string{"Idempotency-Key": "http-flow-approved"})
	assertHTTPStatus(t, replayedRequestResult, http.StatusCreated)
	if replayed := decodeHTTPFlowResponse[httpFlowAccessRequest](t, replayedRequestResult.body); replayed.ID != approvedRequest.ID {
		t.Fatalf("idempotent request IDs differ: %s != %s", replayed.ID, approvedRequest.ID)
	}

	waitForHTTPFlow(t, 3*time.Second, "approval notification", func() bool {
		return feishuPlatform.hasMessage(approver.FeishuOpenID, "interactive", approvedRequest.ID)
	})
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/approvals/pending?limit=50", approver.ID, nil, nil), http.StatusNotFound)
	pending := pendingApprovalForRequest(t, repos, database, approvedRequest.ID)
	callbackBody := marshalHTTPFlowJSON(t, map[string]any{
		"header": map[string]any{"event_id": "http-flow-callback-1", "tenant_key": "tenant-http-flow"},
		"event": map[string]any{
			"operator": map[string]any{"operator_id": map[string]any{"open_id": approver.FeishuOpenID}},
			"action":   map[string]any{"value": map[string]any{"approval_id": pending.ID, "decision": "approved", "comment": "approved by integration flow"}},
		},
	})
	callbackResult := performSignedHTTPFlowCallback(t, plainClient, controlPlane.URL, callbackBody, "http-flow-callback-1")
	assertHTTPStatus(t, callbackResult, http.StatusOK)
	if status := decodeHTTPFlowResponse[map[string]string](t, callbackResult.body)["status"]; status != "processed" {
		t.Fatalf("first callback status = %q", status)
	}
	callbackReplay := performSignedHTTPFlowCallback(t, plainClient, controlPlane.URL, callbackBody, "http-flow-callback-1")
	assertHTTPStatus(t, callbackReplay, http.StatusOK)
	if status := decodeHTTPFlowResponse[map[string]string](t, callbackReplay.body)["status"]; status != "already_processed" {
		t.Fatalf("replayed callback status = %q", status)
	}

	var runningSession httpFlowSession
	waitForHTTPFlow(t, 6*time.Second, "running session", func() bool {
		result := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/access-requests/"+approvedRequest.ID+"/session", "", nil, nil)
		if result.status != http.StatusOK {
			return false
		}
		runningSession = decodeHTTPFlowResponse[httpFlowSession](t, result.body)
		return runningSession.Status == string(domain.SessionRunning)
	})
	if controller.startCalls() != 1 || runningSession.GatewayID != gatewayRecord.ID ||
		runningSession.ConnectionMode != gateway.ConnectionModeNative || !runningSession.CanConnect ||
		runningSession.SourceIP != httpFlowSourceIP || runningSession.TargetAccount != httpFlowTargetAccount ||
		runningSession.GatewayEndpoint != "gateway.test:32001" ||
		runningSession.GatewayHost != "gateway.test" || runningSession.GatewayPort != 32001 ||
		runningSession.ListenerPort != 20000 || runningSession.ExposureMode != "kubernetes_nodeport" {
		t.Fatalf("running session = %+v starts=%d", runningSession, controller.startCalls())
	}
	waitForHTTPFlow(t, 3*time.Second, "session-ready notification", func() bool {
		return feishuPlatform.hasMessage(applicant.FeishuOpenID, "text", "会话已就绪")
	})

	getSessionResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/sessions/"+runningSession.ID, "", nil, nil)
	assertHTTPStatus(t, getSessionResult, http.StatusOK)
	if strings.Contains(string(getSessionResult.body), "token") {
		t.Fatalf("GET session exposed a token field: %s", getSessionResult.body)
	}
	secondReplicaSession := performHTTPRequest(t, applicantClient, http.MethodGet, secondControlPlane.URL+"/api/v1/sessions/"+runningSession.ID, "", nil, nil)
	assertHTTPStatus(t, secondReplicaSession, http.StatusOK)
	if value := decodeHTTPFlowResponse[httpFlowSession](t, secondReplicaSession.body); value.GatewayEndpoint != runningSession.GatewayEndpoint || value.ConnectionMode != gateway.ConnectionModeNative || !value.CanConnect {
		t.Fatalf("second replica session = %+v", value)
	}
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodPost, secondControlPlane.URL+"/api/v1/sessions/"+runningSession.ID+"/token", "", nil, nil), http.StatusNotFound)
	storedSession, err := repos.sessions.GetByID(ctx, database, runningSession.ID)
	if err != nil || storedSession.TokenHash != nil || storedSession.ListenerPort == nil || *storedSession.ListenerPort != 20000 ||
		storedSession.ConnectionMode != gateway.ConnectionModeNative || storedSession.TunnelClientPublicKey != "" || storedSession.TunnelServerCertificate != "" ||
		storedSession.ExternalPort == nil || *storedSession.ExternalPort != 32001 || storedSession.ExposureRef == nil {
		t.Fatalf("stored direct session = %+v err=%v", storedSession, err)
	}
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodPost, secondControlPlane.URL+"/api/v1/sessions/"+runningSession.ID+"/credential", "", nil, nil), http.StatusNotFound)

	connectionID := id.New()
	connectedAt := time.Now().UTC().Add(-time.Second)
	backendSourceIP := "10.20.0.15"
	backendSourcePort := 45678
	gatewayEventBody := marshalHTTPFlowJSON(t, map[string]any{"events": []map[string]any{
		{
			"event_id": id.New(), "gateway_id": gatewayRecord.ID, "connection_id": connectionID,
			"session_id": runningSession.ID, "event_type": "connect_attempt", "source_ip": httpFlowSourceIP,
			"result": "accepted", "occurred_at": connectedAt.Add(-time.Millisecond),
		},
		{
			"event_id": id.New(), "gateway_id": gatewayRecord.ID, "connection_id": connectionID,
			"session_id": runningSession.ID, "event_type": "backend_connected", "source_ip": httpFlowSourceIP,
			"backend_source_ip": backendSourceIP, "backend_source_port": backendSourcePort,
			"result": "success", "occurred_at": connectedAt,
		},
	}})
	auditHeaders := map[string]string{
		gateway.AuditGatewayIDHeader: gatewayRecord.ID,
		gatewayauth.SessionIDHeader:  runningSession.ID,
		gateway.AuditSecretHeader:    components.HTTP.SessionAuditCredentials.Issue(gatewayRecord.ID, runningSession.ID, time.Now().Add(cfg.SessionMaxTTL)),
	}
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/gateway/events/batch", "", gatewayEventBody, map[string]string{"X-Gateway-Internal-Secret": "wrong-secret"}), http.StatusForbidden)
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/gateway/events/batch", "", gatewayEventBody, auditHeaders), http.StatusOK)
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/gateway/events/batch", "", gatewayEventBody, auditHeaders), http.StatusOK)

	operationEventID := id.New()
	operationBody := marshalHTTPFlowJSON(t, map[string]any{"events": []map[string]any{{
		"event_id": operationEventID, "protocol": "postgresql", "asset_id": asset.ID, "target_port": 5432,
		"actual_account": httpFlowTargetAccount, "operation_type": "select", "statement_fingerprint": "sha256:catalog-read",
		"normalized_operation": "SELECT FROM pg_catalog.pg_tables", "object_name": "pg_catalog.pg_tables",
		"result": "success", "duration_ms": 12, "backend_source_ip": backendSourceIP,
		"backend_source_port": backendSourcePort, "source_record_id": "pgaudit:http-flow:1",
		"occurred_at": connectedAt.Add(time.Millisecond), "metadata": map[string]any{"collector": "pgaudit"},
	}}})
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/audit/operations/batch", "", operationBody, map[string]string{"X-Audit-Collector-Secret": "wrong-secret"}), http.StatusForbidden)
	operationResult := performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/audit/operations/batch", "", operationBody, map[string]string{"X-Audit-Collector-Secret": httpFlowCollectorSecret})
	assertHTTPStatus(t, operationResult, http.StatusOK)
	if inserted := decodeHTTPFlowResponse[map[string]any](t, operationResult.body)["inserted"]; inserted != float64(1) {
		t.Fatalf("operation insert response = %s", operationResult.body)
	}
	replayedOperation := performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/audit/operations/batch", "", operationBody, map[string]string{"X-Audit-Collector-Secret": httpFlowCollectorSecret})
	assertHTTPStatus(t, replayedOperation, http.StatusOK)
	if inserted := decodeHTTPFlowResponse[map[string]any](t, replayedOperation.body)["inserted"]; inserted != float64(0) {
		t.Fatalf("replayed operation response = %s", replayedOperation.body)
	}
	operationList := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/operation-audit-events?session_id="+url.QueryEscape(runningSession.ID)+"&actual_account="+httpFlowTargetAccount+"&correlation_status=matched", admin.ID, nil, nil)
	assertHTTPStatus(t, operationList, http.StatusOK)
	operations := decodeHTTPFlowResponse[[]httpFlowOperationAudit](t, operationList.body)
	if len(operations) != 1 || operations[0].EventID != operationEventID || operations[0].ConnectionID != connectionID || operations[0].SessionID != runningSession.ID || operations[0].CorrelationStatus != "matched" {
		t.Fatalf("operation audit list = %s", operationList.body)
	}
	mismatchEventID := id.New()
	unmatchedEventID := id.New()
	additionalOperations := marshalHTTPFlowJSON(t, map[string]any{"events": []map[string]any{
		{
			"event_id": mismatchEventID, "protocol": "postgresql", "asset_id": asset.ID, "target_port": 5432,
			"actual_account": "postgres", "operation_type": "alter_role", "result": "denied",
			"backend_source_ip": backendSourceIP, "backend_source_port": backendSourcePort,
			"source_record_id": "pgaudit:http-flow:2", "occurred_at": connectedAt.Add(2 * time.Millisecond),
			"metadata": map[string]any{"collector": "pgaudit"},
		},
		{
			"event_id": unmatchedEventID, "protocol": "postgresql", "asset_id": asset.ID, "target_port": 5432,
			"actual_account": httpFlowTargetAccount, "operation_type": "select", "result": "success",
			"backend_source_ip": backendSourceIP, "backend_source_port": backendSourcePort + 1,
			"source_record_id": "pgaudit:http-flow:3", "occurred_at": connectedAt.Add(3 * time.Millisecond),
			"metadata": map[string]any{"collector": "pgaudit"},
		},
	}})
	additionalResult := performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/audit/operations/batch", "", additionalOperations, map[string]string{"X-Audit-Collector-Secret": httpFlowCollectorSecret})
	assertHTTPStatus(t, additionalResult, http.StatusOK)
	if inserted := decodeHTTPFlowResponse[map[string]any](t, additionalResult.body)["inserted"]; inserted != float64(2) {
		t.Fatalf("additional operation response = %s", additionalResult.body)
	}

	secondConnectionID := id.New()
	secondConnectedAt := connectedAt.Add(4 * time.Millisecond)
	secondConnection := marshalHTTPFlowJSON(t, map[string]any{
		"event_id": id.New(), "gateway_id": gatewayRecord.ID, "connection_id": secondConnectionID,
		"session_id": runningSession.ID, "event_type": "backend_connected", "source_ip": httpFlowSourceIP,
		"backend_source_ip": backendSourceIP, "backend_source_port": backendSourcePort,
		"result": "success", "occurred_at": secondConnectedAt,
	})
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/gateway/events", "", secondConnection, auditHeaders), http.StatusOK)
	ambiguousEventID := id.New()
	ambiguousOperation := marshalHTTPFlowJSON(t, map[string]any{"events": []map[string]any{{
		"event_id": ambiguousEventID, "protocol": "postgresql", "asset_id": asset.ID, "target_port": 5432,
		"actual_account": httpFlowTargetAccount, "operation_type": "select", "result": "success",
		"backend_source_ip": backendSourceIP, "backend_source_port": backendSourcePort,
		"source_record_id": "pgaudit:http-flow:4", "occurred_at": secondConnectedAt.Add(time.Millisecond),
		"metadata": map[string]any{"collector": "pgaudit"},
	}}})
	assertHTTPStatus(t, performHTTPRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/internal/audit/operations/batch", "", ambiguousOperation, map[string]string{"X-Audit-Collector-Secret": httpFlowCollectorSecret}), http.StatusOK)

	mismatchList := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/operation-audit-events?session_id="+url.QueryEscape(runningSession.ID)+"&correlation_status=identity_mismatch", admin.ID, nil, nil)
	assertHTTPStatus(t, mismatchList, http.StatusOK)
	mismatches := decodeHTTPFlowResponse[[]httpFlowOperationAudit](t, mismatchList.body)
	if len(mismatches) != 1 || mismatches[0].EventID != mismatchEventID || mismatches[0].ActualAccount != "postgres" {
		t.Fatalf("identity mismatch audit list = %s", mismatchList.body)
	}
	unmatchedList := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/operation-audit-events?asset_id="+url.QueryEscape(asset.ID)+"&correlation_status=unmatched", admin.ID, nil, nil)
	assertHTTPStatus(t, unmatchedList, http.StatusOK)
	unmatched := decodeHTTPFlowResponse[[]httpFlowOperationAudit](t, unmatchedList.body)
	if len(unmatched) != 2 || unmatched[0].EventID != ambiguousEventID || unmatched[0].Metadata["correlation_reason"] != "ambiguous_connection" || unmatched[1].EventID != unmatchedEventID || unmatched[1].Metadata["correlation_reason"] != "connection_not_found" {
		t.Fatalf("unmatched operation audit list = %s", unmatchedList.body)
	}
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/operation-audit-events", "", nil, nil), http.StatusForbidden)
	eventsResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/sessions/"+runningSession.ID+"/events?limit=100", "", nil, nil)
	assertHTTPStatus(t, eventsResult, http.StatusOK)
	if !containsHTTPFlowEvent(decodeHTTPFlowResponse[[]httpFlowEvent](t, eventsResult.body), "session.started") || !containsHTTPFlowEvent(decodeHTTPFlowResponse[[]httpFlowEvent](t, eventsResult.body), "connection.backend_connected") {
		t.Fatalf("session event history = %s", eventsResult.body)
	}

	closeResult := performHTTPRequest(t, applicantClient, http.MethodPost, controlPlane.URL+"/api/v1/sessions/"+runningSession.ID+"/close", "", nil, nil)
	assertHTTPStatus(t, closeResult, http.StatusOK)
	waitForHTTPFlow(t, 6*time.Second, "closed session", func() bool {
		result := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/sessions/"+runningSession.ID, "", nil, nil)
		if result.status != http.StatusOK {
			return false
		}
		return decodeHTTPFlowResponse[httpFlowSession](t, result.body).Status == string(domain.SessionClosed)
	})
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodPost, controlPlane.URL+"/api/v1/sessions/"+runningSession.ID+"/close", "", nil, nil), http.StatusOK)
	if controller.stopCalls() != 1 {
		t.Fatalf("Gateway Agent stop calls = %d, want 1", controller.stopCalls())
	}

	rejectedRequest := createHTTPFlowRequest(t, applicantClient, controlPlane.URL, region.ID, asset.ID, "http-flow-rejected")
	rejectedApproval := pendingApprovalForRequest(t, repos, database, rejectedRequest.ID)
	rejectResult := performJSONRequest(t, plainClient, http.MethodPost, controlPlane.URL+"/api/v1/approvals/"+rejectedApproval.ID+"/reject", approver.ID, map[string]any{"comment": "rejected from the web approval page"}, nil)
	assertHTTPStatus(t, rejectResult, http.StatusOK)
	requestResult := performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/access-requests/"+rejectedRequest.ID, "", nil, nil)
	assertHTTPStatus(t, requestResult, http.StatusOK)
	if value := decodeHTTPFlowResponse[httpFlowAccessRequest](t, requestResult.body); value.Status != string(domain.AccessRequestRejected) {
		t.Fatalf("rejected request = %+v", value)
	}
	assertHTTPStatus(t, performHTTPRequest(t, applicantClient, http.MethodGet, controlPlane.URL+"/api/v1/access-requests/"+rejectedRequest.ID+"/session", "", nil, nil), http.StatusNotFound)

	cancelledRequest := createHTTPFlowRequest(t, applicantClient, controlPlane.URL, region.ID, asset.ID, "http-flow-cancelled")
	cancelledApproval := pendingApprovalForRequest(t, repos, database, cancelledRequest.ID)
	cancelResult := performHTTPRequest(t, applicantClient, http.MethodPost, controlPlane.URL+"/api/v1/access-requests/"+cancelledRequest.ID+"/cancel", "", nil, nil)
	assertHTTPStatus(t, cancelResult, http.StatusOK)
	if value := decodeHTTPFlowResponse[httpFlowAccessRequest](t, cancelResult.body); value.Status != string(domain.AccessRequestCancelled) {
		t.Fatalf("cancelled request = %+v", value)
	}
	cancelledDecision := performApprovalCallback(t, plainClient, controlPlane.URL, approver.FeishuOpenID, cancelledApproval.ID, "approved", "late approval", "http-flow-callback-cancelled")
	assertHTTPStatus(t, cancelledDecision, http.StatusOK)
	if status := decodeHTTPFlowResponse[map[string]string](t, cancelledDecision.body)["status"]; status != "already_processed" {
		t.Fatalf("cancelled approval callback status = %q", status)
	}

	auditsResult := performHTTPRequest(t, plainClient, http.MethodGet, controlPlane.URL+"/api/v1/audit-events?session_id="+url.QueryEscape(runningSession.ID)+"&limit=200", admin.ID, nil, nil)
	assertHTTPStatus(t, auditsResult, http.StatusOK)
	audits := decodeHTTPFlowResponse[[]httpFlowAudit](t, auditsResult.body)
	if !containsHTTPFlowAudit(audits, "session.revoke_requested") {
		t.Errorf("user close operation is missing: %s", auditsResult.body)
	}
	for _, eventType := range []string{"session.provisioning", "session.started", "connection.connect_attempt", "connection.backend_connected", "session.closed"} {
		if containsHTTPFlowAudit(audits, eventType) {
			t.Errorf("runtime evidence leaked into user operation log: %s", auditsResult.body)
		}
	}

	notificationsComplete := false
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); {
		notificationsComplete = feishuPlatform.hasMessage(applicant.FeishuOpenID, "text", "申请状态更新") &&
			feishuPlatform.hasMessage(applicant.FeishuOpenID, "text", "会话已就绪") &&
			feishuPlatform.hasMessage(applicant.FeishuOpenID, "text", "会话已关闭")
		if notificationsComplete {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !notificationsComplete {
		t.Fatalf("timed out waiting for result and lifecycle notifications: messages=%+v unexpected=%v", feishuPlatform.messagesSnapshot(), feishuPlatform.unexpectedSnapshot())
	}
	for _, message := range feishuPlatform.messagesSnapshot() {
		if strings.Contains(message.Content, httpFlowTarget) || strings.Contains(message.RawBody, httpFlowTarget) {
			t.Errorf("Feishu message leaked target address: %+v", message)
		}
	}
	if unexpected := feishuPlatform.unexpectedSnapshot(); len(unexpected) != 0 {
		t.Fatalf("unexpected fake Feishu requests: %v", unexpected)
	}
}

type httpFlowRegion struct {
	ID string `json:"id"`
}

type httpFlowGateway struct {
	ID string `json:"id"`
}

type httpFlowAsset struct {
	ID string `json:"id"`
}

type httpFlowCatalog struct {
	Version   int    `json:"version"`
	GatewayID string `json:"gateway_id"`
	Assets    []struct {
		TargetID string `json:"target_id"`
		Ports    []int  `json:"ports"`
	} `json:"assets"`
}

type httpFlowAccessRequest struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	SourceIP      string `json:"source_ip"`
	TargetAccount string `json:"target_account"`
}

type httpFlowSession struct {
	ConnectionMode  string `json:"connection_mode"`
	CanConnect      bool   `json:"can_connect"`
	SourceIP        string `json:"source_ip"`
	TargetAccount   string `json:"target_account"`
	ID              string `json:"id"`
	GatewayID       string `json:"gateway_id"`
	Status          string `json:"status"`
	GatewayEndpoint string `json:"gateway_endpoint"`
	GatewayHost     string `json:"gateway_host"`
	GatewayPort     int    `json:"gateway_port"`
	ListenerPort    int    `json:"listener_port"`
	ExposureMode    string `json:"exposure_mode"`
}

type httpFlowOperationAudit struct {
	EventID           string         `json:"event_id"`
	ConnectionID      string         `json:"connection_id"`
	SessionID         string         `json:"session_id"`
	ActualAccount     string         `json:"actual_account"`
	CorrelationStatus string         `json:"correlation_status"`
	Metadata          map[string]any `json:"metadata"`
}

type httpFlowEvent struct {
	EventType string `json:"event_type"`
}

type httpFlowAudit struct {
	EventType string `json:"event_type"`
}

type httpFlowHTTPResult struct {
	status int
	header http.Header
	body   []byte
}

// The flow injects a simulated management client directly. Production runtime
// selection is covered separately by the session runtime integration tests.
type httpFlowComponents struct {
	HTTP   *httpapi.Server
	Worker *worker.Runner
}

// The approved runtime keeps the worker-to-agent HTTP transport under test
// while accepting only the target decrypted from the approved asset.
type httpFlowSessionRuntime struct {
	*gateway.HTTPClient
	endpoint string
}

func (r *httpFlowSessionRuntime) PublicHost() string  { return "gateway.test" }
func (r *httpFlowSessionRuntime) RuntimeMode() string { return "kubernetes" }
func (r *httpFlowSessionRuntime) CreateApprovedSession(ctx context.Context, _ string, request gateway.CreateSessionRequest, target string) (gateway.CreateSessionResponse, error) {
	if target != httpFlowTarget {
		return gateway.CreateSessionResponse{}, errors.New("runtime did not receive the approved target")
	}
	return r.HTTPClient.CreateSession(ctx, r.endpoint, request)
}
func (r *httpFlowSessionRuntime) CloseSession(ctx context.Context, _, sessionID, key string) (gateway.CloseSessionResponse, error) {
	return r.HTTPClient.CloseSession(ctx, r.endpoint, sessionID, key)
}
func (r *httpFlowSessionRuntime) GetSession(ctx context.Context, _, sessionID string) (gateway.SessionStatusResponse, error) {
	return r.HTTPClient.GetSession(ctx, r.endpoint, sessionID)
}
func (r *httpFlowSessionRuntime) CheckReady(ctx context.Context, _ string) error {
	return r.HTTPClient.CheckReady(ctx, r.endpoint)
}
func (r *httpFlowSessionRuntime) GetReadiness(ctx context.Context, _ string) (gateway.ReadinessReport, error) {
	return r.HTTPClient.GetReadiness(ctx, r.endpoint)
}

func newHTTPFlowComponents(t *testing.T, ctx context.Context, database *sql.DB, cfg config.Config, client gateway.Client) httpFlowComponents {
	t.Helper()
	cipher := func(keyID, purpose string) secretstore.Cipher {
		value, err := secretstore.NewAESGCM(keyID, security.DeriveKey(cfg.EncryptionKey, purpose))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	systemSettings, err := service.NewSystemSettingsService(database, cipher("settings-master-v1", "system-settings"), cfg.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := systemSettings.Current(ctx); err != nil {
		t.Fatal(err)
	}
	transport, err := service.NewBrowserTransportService(database, cipher("browser-transport-v1", "browser-transport"))
	if err != nil {
		t.Fatal(err)
	}
	assetCipher, err := secretstore.NewAESGCMFromFile(cfg.AssetEncryptionKeyID, cfg.AssetEncryptionKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	sessionSigner, err := security.NewSessionSigner(string(security.DeriveKey(cfg.EncryptionKey, "browser-session")))
	if err != nil {
		t.Fatal(err)
	}
	auditCredentials, err := gatewayauth.NewSessionCredentials(security.DeriveKey(cfg.EncryptionKey, "session-agent-audit"))
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := observability.NewMetrics("access_gateway")
	if err != nil {
		t.Fatal(err)
	}
	repos := newRepositories()
	queue := worker.NewQueue(256)
	oauthStates := repository.NewOAuthStateRepository()
	svc, err := service.NewAccessService(service.ServiceOptions{
		PublicURL: cfg.PublicURL, DB: database, Gateway: client,
		Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions,
		SessionEvents: repos.sessionEvents, Audits: repos.audits, Outbox: repos.outbox,
		OAuthStates: oauthStates, Tasks: queue, Logger: zerolog.Nop(),
		DefaultTTL: cfg.SessionDefaultTTL, MaxTTL: cfg.SessionMaxTTL, ApprovalTimeout: cfg.ApprovalTimeout,
		GatewayHeartbeatMaxAge: cfg.GatewayHeartbeatMaxAge, AdminUserIDs: cfg.AdminUserIDs,
		SystemSettings: systemSettings, Notifier: systemSettings, AuditProfiles: systemSettings,
		IdentityCipher: cipher("identity-v1", "identity-security"), AssetEncryptor: assetCipher,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := worker.NewRunnerWithOptions(queue, svc, zerolog.Nop(), worker.RunnerOptions{
		RecoveryInterval: time.Minute, GatewayHealthInterval: cfg.GatewayHealthInterval,
		GatewayHealthFailureThreshold: cfg.GatewayHealthFailureThreshold, Metrics: metrics,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := httpapi.NewServerWithOptions(httpapi.ServerOptions{
		PublicURL: cfg.PublicURL, Transport: transport, Service: svc, DB: database,
		Settings: systemSettings, Authentication: svc, AllowDevAuth: cfg.AllowDevAuth,
		SessionSigner: sessionSigner, SessionAuditCredentials: auditCredentials,
		AuditCollectorSecret: cfg.AuditCollectorSecret, Logger: zerolog.Nop(),
		CallbackEvents: repository.NewCallbackEventRepository(), OAuthStates: oauthStates,
		Metrics: metrics, MetricsEnabled: cfg.MetricsEnabled, MetricsBearerToken: cfg.MetricsBearerToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	return httpFlowComponents{HTTP: server, Worker: runner}
}

func createHTTPFlowUser(t *testing.T, ctx context.Context, repos repositories, database *sql.DB, openID, name string) domain.User {
	t.Helper()
	user, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), FeishuOpenID: openID, Nickname: name, Status: domain.UserStatusActive})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return user
}

func createHTTPFlowRequest(t *testing.T, client *http.Client, baseURL, regionID, assetID, idempotencyKey string) httpFlowAccessRequest {
	t.Helper()
	result := performJSONRequest(t, client, http.MethodPost, baseURL+"/api/v1/access-requests", "", map[string]any{
		"region_id": regionID, "asset_id": assetID, "target_port": 5432,
		"source_ip": httpFlowSourceIP, "target_account": httpFlowTargetAccount,
		"reason": "validate " + idempotencyKey, "ttl_seconds": 120,
	}, map[string]string{"Idempotency-Key": idempotencyKey})
	assertHTTPStatus(t, result, http.StatusCreated)
	return decodeHTTPFlowResponse[httpFlowAccessRequest](t, result.body)
}

func pendingApprovalForRequest(t *testing.T, repos repositories, database *sql.DB, requestID string) domain.Approval {
	t.Helper()
	values, err := repos.approvals.ListByRequest(context.Background(), database, requestID)
	if err != nil {
		t.Fatalf("list approvals for request %s: %v", requestID, err)
	}
	for _, approval := range values {
		if approval.Decision == nil {
			return approval
		}
	}
	t.Fatalf("pending approval for request %s not found: %+v", requestID, values)
	return domain.Approval{}
}

func performApprovalCallback(t *testing.T, client *http.Client, baseURL, approverOpenID, approvalID, decision, comment, eventID string) httpFlowHTTPResult {
	t.Helper()
	body := marshalHTTPFlowJSON(t, map[string]any{
		"header": map[string]any{"event_id": eventID, "tenant_key": "tenant-http-flow"},
		"event": map[string]any{
			"operator": map[string]any{"operator_id": map[string]any{"open_id": approverOpenID}},
			"action": map[string]any{"value": map[string]any{
				"approval_id": approvalID, "decision": decision, "comment": comment,
			}},
		},
	})
	return performSignedHTTPFlowCallback(t, client, baseURL, body, eventID)
}

func performSignedHTTPFlowCallback(t *testing.T, client *http.Client, baseURL string, body []byte, eventID string) httpFlowHTTPResult {
	t.Helper()
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "nonce-" + eventID
	digest := sha256.Sum256(append(append(append([]byte(timestamp), []byte(nonce)...), []byte(httpFlowCallbackSecret)...), body...))
	return performHTTPRequest(t, client, http.MethodPost, baseURL+"/callbacks/feishu", "", body, map[string]string{
		"X-Lark-Request-Timestamp": timestamp,
		"X-Lark-Request-Nonce":     nonce,
		"X-Lark-Signature":         hex.EncodeToString(digest[:]),
	})
}

func newNoRedirectClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create HTTP cookie jar: %v", err)
	}
	return &http.Client{
		Timeout: 2 * time.Second,
		Jar:     jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func performJSONRequest(t *testing.T, client *http.Client, method, target, userID string, payload any, headers map[string]string) httpFlowHTTPResult {
	t.Helper()
	if method == http.MethodPost && strings.HasSuffix(target, "/api/v1/admin/assets") {
		origin := strings.TrimSuffix(target, "/api/v1/admin/assets")
		challengeResult := performHTTPRequest(t, client, http.MethodPost, origin+"/api/v1/auth/transport/challenges", userID,
			marshalHTTPFlowJSON(t, map[string]string{"method": method, "path": "/api/v1/admin/assets"}), map[string]string{"Origin": origin})
		assertHTTPStatus(t, challengeResult, http.StatusOK)
		challenge := decodeHTTPFlowResponse[securetransport.Challenge](t, challengeResult.body)
		envelope, encryptedClient, err := testclient.Seal(challenge, marshalHTTPFlowJSON(t, payload))
		if err != nil {
			t.Fatal(err)
		}
		result := performHTTPRequest(t, client, method, target, userID, marshalHTTPFlowJSON(t, envelope), headers)
		if result.header.Get("X-AG-Encrypted") != "1" {
			t.Fatalf("unencrypted asset response: %d", result.status)
		}
		result.body, err = encryptedClient.Open(result.status, result.body)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	return performHTTPRequest(t, client, method, target, userID, marshalHTTPFlowJSON(t, payload), headers)
}

func performHTTPRequest(t *testing.T, client *http.Client, method, target, userID string, body []byte, headers map[string]string) httpFlowHTTPResult {
	t.Helper()
	request, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s: %v", method, target, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if userID != "" {
		request.Header.Set("X-User-ID", userID)
	}
	if client.Jar != nil && method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		request.Header.Set("Origin", request.URL.Scheme+"://"+request.URL.Host)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform %s %s: %v", method, target, err)
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, target, err)
	}
	return httpFlowHTTPResult{status: response.StatusCode, header: response.Header.Clone(), body: encoded}
}

func marshalHTTPFlowJSON(t *testing.T, value any) []byte {
	t.Helper()
	if value == nil {
		return nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal HTTP flow JSON: %v", err)
	}
	return encoded
}

func decodeHTTPFlowResponse[T any](t *testing.T, body []byte) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode HTTP flow response %q: %v", body, err)
	}
	return value
}

func assertHTTPStatus(t *testing.T, result httpFlowHTTPResult, want int) {
	t.Helper()
	if result.status != want {
		t.Fatalf("HTTP status = %d, want %d, body=%s", result.status, want, result.body)
	}
}

func waitForHTTPFlow(t *testing.T, timeout time.Duration, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func containsHTTPFlowEvent(events []httpFlowEvent, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

func containsHTTPFlowAudit(events []httpFlowAudit, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

type switchableHTTPHandler struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (handler *switchableHTTPHandler) Set(next http.Handler) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.handler = next
}

func (handler *switchableHTTPHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.mu.RLock()
	next := handler.handler
	handler.mu.RUnlock()
	if next == nil {
		http.Error(response, "gateway is not configured", http.StatusServiceUnavailable)
		return
	}
	next.ServeHTTP(response, request)
}

type httpFlowFeishuTransport struct {
	platform *fakeFeishuPlatform
	fallback http.RoundTripper
}

func (t *httpFlowFeishuTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "open.feishu.cn" {
		return t.fallback.RoundTrip(request)
	}
	request = request.Clone(request.Context())
	if path := map[string]string{
		"/open-apis/auth/v3/app_access_token/internal": "/oauth/app-token",
		"/open-apis/authen/v1/access_token":            "/oauth/token",
		"/open-apis/authen/v1/user_info":               "/oauth/profile",
	}[request.URL.Path]; path != "" {
		request.URL.Path = path
	}
	response := httptest.NewRecorder()
	t.platform.ServeHTTP(response, request)
	return response.Result(), nil
}

type fakeFeishuMessage struct {
	ReceiveID string
	MsgType   string
	Content   string
	RawBody   string
}

type fakeFeishuPlatform struct {
	mu         sync.Mutex
	messages   []fakeFeishuMessage
	unexpected []string
}

func newFakeFeishuPlatform() *fakeFeishuPlatform { return &fakeFeishuPlatform{} }

func (platform *fakeFeishuPlatform) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/oauth/app-token":
		if request.Method != http.MethodPost {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var credentials map[string]string
		if json.NewDecoder(request.Body).Decode(&credentials) != nil || credentials["app_id"] != "http-flow-app" || credentials["app_secret"] != "http-flow-app-secret" {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		writeFakeFeishuJSON(response, map[string]any{"code": 0, "app_access_token": "fake-app-access-token"})
	case "/oauth/token":
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer fake-app-access-token" {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		var exchange map[string]string
		if json.NewDecoder(request.Body).Decode(&exchange) != nil || exchange["grant_type"] != "authorization_code" || exchange["code"] != "http-flow-code" {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		writeFakeFeishuJSON(response, map[string]any{"code": 0, "data": map[string]string{"access_token": "fake-user-access-token"}})
	case "/oauth/profile":
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer fake-user-access-token" {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeFakeFeishuJSON(response, map[string]any{"code": 0, "data": map[string]any{
			"open_id": "ou-http-applicant", "union_id": "on-http-applicant", "tenant_key": "tenant-http-flow",
			"name": "HTTP Applicant", "email": "applicant@example.test", "department": "Platform", "active": true,
		}})
	case "/open-apis/auth/v3/tenant_access_token/internal":
		if request.Method != http.MethodPost {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var credentials map[string]string
		if json.NewDecoder(request.Body).Decode(&credentials) != nil || credentials["app_id"] != "http-flow-app" || credentials["app_secret"] != "http-flow-app-secret" {
			platform.recordUnexpected(request)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		writeFakeFeishuJSON(response, map[string]any{"code": 0, "tenant_access_token": "fake-tenant-access-token", "expire": 3600})
	case "/open-apis/im/v1/messages":
		platform.captureMessage(response, request)
	default:
		platform.recordUnexpected(request)
		response.WriteHeader(http.StatusNotFound)
		writeFakeFeishuJSON(response, map[string]any{"code": 404, "msg": "not found"})
	}
}

func (platform *fakeFeishuPlatform) captureMessage(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer fake-tenant-access-token" || request.URL.Query().Get("receive_id_type") != "open_id" {
		platform.recordUnexpected(request)
		response.WriteHeader(http.StatusUnauthorized)
		return
	}
	encoded, err := io.ReadAll(io.LimitReader(request.Body, 1<<20))
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	var payload struct {
		ReceiveID string `json:"receive_id"`
		MsgType   string `json:"msg_type"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal(encoded, &payload); err != nil || payload.ReceiveID == "" || payload.MsgType == "" || payload.Content == "" {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	platform.mu.Lock()
	platform.messages = append(platform.messages, fakeFeishuMessage{ReceiveID: payload.ReceiveID, MsgType: payload.MsgType, Content: payload.Content, RawBody: string(encoded)})
	platform.mu.Unlock()
	writeFakeFeishuJSON(response, map[string]any{"code": 0})
}

func (platform *fakeFeishuPlatform) hasMessage(receiveID, msgType, contains string) bool {
	platform.mu.Lock()
	defer platform.mu.Unlock()
	for _, message := range platform.messages {
		if message.ReceiveID == receiveID && message.MsgType == msgType && strings.Contains(message.Content, contains) {
			return true
		}
	}
	return false
}

func (platform *fakeFeishuPlatform) messagesSnapshot() []fakeFeishuMessage {
	platform.mu.Lock()
	defer platform.mu.Unlock()
	return append([]fakeFeishuMessage(nil), platform.messages...)
}

func (platform *fakeFeishuPlatform) recordUnexpected(request *http.Request) {
	platform.mu.Lock()
	defer platform.mu.Unlock()
	platform.unexpected = append(platform.unexpected, request.Method+" "+request.URL.String())
}

func (platform *fakeFeishuPlatform) unexpectedSnapshot() []string {
	platform.mu.Lock()
	defer platform.mu.Unlock()
	return append([]string(nil), platform.unexpected...)
}

func writeFakeFeishuJSON(response http.ResponseWriter, value any) {
	_ = json.NewEncoder(response).Encode(value)
}
