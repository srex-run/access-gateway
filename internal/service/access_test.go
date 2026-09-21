package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/gateway"
)

type recordingEncryptor struct {
	plaintext []byte
	aad       []byte
}

func TestNativeTCPGatewayResponseModeIsExplicit(t *testing.T) {
	const sessionID = "11111111-1111-4111-8111-111111111111"
	valid := gateway.CreateSessionResponse{
		SessionID: sessionID, Status: "running", ConnectionMode: gateway.ConnectionModeNative,
		ProcessID: "tcp-20000", ListenerPort: 20000, ExternalPort: 20000,
		ExposureMode: "direct", ExposureRef: "direct/20000",
	}
	if !validGatewayCreateResponse(valid, sessionID, gateway.ConnectionModeNative) {
		t.Fatal("native response rejected")
	}
	for _, mode := range []string{"", gateway.ConnectionModeDirect, gateway.ConnectionModeTunnel, "unknown"} {
		response := valid
		response.ConnectionMode = mode
		if validGatewayCreateResponse(response, sessionID, gateway.ConnectionModeNative) {
			t.Fatalf("mismatched native response accepted: %q", mode)
		}
	}
	valid.ServerCertificate = "unexpected certificate"
	if validGatewayCreateResponse(valid, sessionID, gateway.ConnectionModeNative) {
		t.Fatal("native response with tunnel identity accepted")
	}
}

type credentialResolverFunc func(context.Context, string) ([][]byte, error)

func (f credentialResolverFunc) Resolve(ctx context.Context, reference string) ([][]byte, error) {
	return f(ctx, reference)
}

func TestValidateGatewayCredentialReferenceFailsClosedAndClearsMaterial(t *testing.T) {
	credential := []byte("audit---0123456789abcdef0123456789")
	service := &AccessService{gatewayCredentials: credentialResolverFunc(func(_ context.Context, reference string) ([][]byte, error) {
		if reference != "gateway-cn-east-1" {
			t.Fatalf("reference = %q", reference)
		}
		return [][]byte{credential}, nil
	})}
	if err := service.validateGatewayCredentialReference(context.Background(), "gateway-cn-east-1"); err != nil {
		t.Fatalf("validateGatewayCredentialReference: %v", err)
	}
	for _, value := range credential {
		if value != 0 {
			t.Fatal("resolved credential was not cleared")
		}
	}

	service.gatewayCredentials = credentialResolverFunc(func(context.Context, string) ([][]byte, error) {
		return nil, errors.New("secret unavailable: gateway-cn-east-1")
	})
	if err := service.validateGatewayCredentialReference(context.Background(), "gateway-cn-east-1"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unavailable credential error = %v", err)
	} else if strings.Contains(err.Error(), "gateway-cn-east-1") {
		t.Fatalf("credential validation error leaked its reference: %v", err)
	}
}

func TestNormalizeGatewayCredentialReference(t *testing.T) {
	value, err := normalizeGatewayCredentialReference("  gateway-cn-east-1  ", true)
	if err != nil || value != "gateway-cn-east-1" {
		t.Fatalf("normalized reference = %q, %v", value, err)
	}
	for _, value := range []string{"", "../gateway", ".hidden", "gateway/secret"} {
		if _, err := normalizeGatewayCredentialReference(value, true); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid reference %q error = %v", value, err)
		}
	}
}

func (e *recordingEncryptor) Encrypt(_ context.Context, plaintext, associatedData []byte) (string, error) {
	e.plaintext = append([]byte(nil), plaintext...)
	e.aad = append([]byte(nil), associatedData...)
	return "agk1.encrypted", nil
}

func TestProtectAssetTargetEncryptsWithAssetIdentity(t *testing.T) {
	encryptor := &recordingEncryptor{}
	service := &AccessService{assetEncryptor: encryptor}
	ciphertext, err := service.protectAssetTarget(context.Background(), "asset-id", "10.0.0.8", "")
	if err != nil || ciphertext != "agk1.encrypted" {
		t.Fatalf("protectAssetTarget ciphertext=%q err=%v", ciphertext, err)
	}
	if string(encryptor.plaintext) != "10.0.0.8" || string(encryptor.aad) != "asset-id" {
		t.Fatalf("encryption inputs plaintext=%q aad=%q", encryptor.plaintext, encryptor.aad)
	}
	if _, err := service.protectAssetTarget(context.Background(), "asset-id", "10.0.0.8", "caller-ciphertext"); err == nil {
		t.Fatal("plaintext and caller ciphertext were accepted together")
	}
	legacy := &AccessService{}
	if value, err := legacy.protectAssetTarget(context.Background(), "asset-id", "", "kms-ciphertext"); err != nil || value != "kms-ciphertext" {
		t.Fatalf("legacy ciphertext value=%q err=%v", value, err)
	}
	if _, err := legacy.protectAssetTarget(context.Background(), "asset-id", "plaintext", ""); err == nil || !strings.Contains(err.Error(), "target_ciphertext") {
		t.Fatalf("legacy plaintext error=%v", err)
	}
}

func TestNextApprovalLevelUsesOneApprovalPerLevel(t *testing.T) {
	approved := domain.ApprovalApproved
	chain := []domain.Approval{
		{ApprovalLevel: 1, Decision: &approved},
		{ApprovalLevel: 1},
		{ApprovalLevel: 2},
	}
	level, complete := nextApprovalLevel(chain)
	if complete || level != 2 {
		t.Fatalf("nextApprovalLevel = %d, %v", level, complete)
	}
	chain[2].Decision = &approved
	if level, complete := nextApprovalLevel(chain); !complete || level != 0 {
		t.Fatalf("completed nextApprovalLevel = %d, %v", level, complete)
	}
}

func TestSameRequestPayload(t *testing.T) {
	start := time.Date(2026, 9, 2, 14, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	ticket := "INC-1"
	sourceIP := "203.0.113.10"
	targetAccount := "readonly"
	existing := domain.AccessRequest{
		ApplicantID: "user", AssetID: "asset", TargetPort: 3306, Reason: "diagnose",
		TicketNo: &ticket, RequestedStartAt: &start, TTLSeconds: 3600,
		SourceIP: &sourceIP, TargetAccount: &targetAccount,
	}
	input := CreateRequestInput{
		ApplicantID: "user", AssetID: "asset", TargetPort: 3306, Reason: "diagnose",
		TicketNo: &ticket, RequestedStartAt: &start, TTLSeconds: 3600,
		SourceIP: sourceIP, TargetAccount: targetAccount,
	}
	if !sameRequestPayload(existing, input) {
		t.Fatal("identical idempotent request did not match")
	}
	input.TargetPort = 5432
	if sameRequestPayload(existing, input) {
		t.Fatal("different idempotent request matched")
	}
}

func TestSanitizeEventMetadataRedactsSecrets(t *testing.T) {
	metadata, err := sanitizeEventMetadata(map[string]any{
		"client": "tailcat-forward",
		"token":  "plaintext-token",
		"nested": map[string]any{"authorization_header": "Bearer secret"},
	})
	if err != nil {
		t.Fatalf("sanitizeEventMetadata: %v", err)
	}
	if metadata["token"] != "[REDACTED]" {
		t.Fatalf("token = %#v", metadata["token"])
	}
	nested := metadata["nested"].(map[string]any)
	if nested["authorization_header"] != "[REDACTED]" || metadata["client"] != "tailcat-forward" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestGatewayEndpointValidationBoundaries(t *testing.T) {
	managementAccepted := []string{
		"https://gateway.example",
		"https://gateway.example/base",
		"https://[2001:db8::1]:443",
	}
	for _, value := range managementAccepted {
		if err := validateManagementEndpoint(value); err != nil {
			t.Errorf("management endpoint %q rejected: %v", value, err)
		}
	}
	managementRejected := []string{
		"https://gateway.example:",
		"https://gateway.example:0",
		"https://gateway.example:65536",
		"https://user:pass@gateway.example",
		"https://gateway.example/path?token=secret",
		"https://gateway.example?",
		"https://gateway.example/path#fragment",
		"https://[fe80::1%25eth0]:443",
	}
	for _, value := range managementRejected {
		if err := validateManagementEndpoint(value); err == nil {
			t.Errorf("invalid management endpoint %q was accepted", value)
		}
	}

	publicAccepted := []string{
		"gateway.example:443",
		"https://gateway.example:443",
		"[2001:db8::1]:443",
		"https://[2001:db8::1]:443/",
	}
	for _, value := range publicAccepted {
		if err := validatePublicEndpoint(value); err != nil {
			t.Errorf("public endpoint %q rejected: %v", value, err)
		}
	}
	publicRejected := []string{
		"gateway.example",
		"gateway.example:",
		"gateway.example:0",
		"gateway.example:65536",
		"https://gateway.example",
		"https://gateway.example:443/path",
		"https://gateway.example:443?token=secret",
		"https://user:pass@gateway.example:443",
		"[fe80::1%eth0]:443",
	}
	for _, value := range publicRejected {
		if err := validatePublicEndpoint(value); err == nil {
			t.Errorf("invalid public endpoint %q was accepted", value)
		}
	}
}

func TestValidGatewayCloseResponseRequiresMatchingTerminalState(t *testing.T) {
	for _, status := range []string{"closed", "expired", "not_found"} {
		if !validGatewayCloseResponse(gateway.CloseSessionResponse{SessionID: "session-1", Status: status}, "session-1") {
			t.Errorf("terminal status %q was rejected", status)
		}
	}
	for _, response := range []gateway.CloseSessionResponse{
		{},
		{SessionID: "session-1"},
		{SessionID: "session-1", Status: "failed"},
		{SessionID: "other", Status: "closed"},
	} {
		if validGatewayCloseResponse(response, "session-1") {
			t.Errorf("malformed close response was accepted: %+v", response)
		}
	}
}
