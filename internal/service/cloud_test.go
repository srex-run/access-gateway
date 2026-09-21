package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/cloudassets"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

func TestCloudCredentialRotationAndIsolation(t *testing.T) {
	old := cloudassets.Credentials{AccessKey: "test-access", SecretKey: "test-secret", SessionToken: "test-token"}
	value, err := mergeCloudCredentials(old, CloudAccountInput{Provider: "aws"})
	if err != nil || value != old {
		t.Fatal("empty edit cleared existing credentials")
	}
	value, err = mergeCloudCredentials(old, CloudAccountInput{Provider: "aws", AccessKey: "new-access", SecretKey: "new-secret"})
	if err != nil || value.SessionToken != "" || value.AccessKey != "new-access" {
		t.Fatal("credential rotation retained an old session token")
	}
	for _, input := range []CloudAccountInput{{AccessKey: "one-half"}, {SecretKey: "one-half"}, {Provider: "huaweicloud"}} {
		if _, err := mergeCloudCredentials(old, input); !errors.Is(err, ErrValidation) {
			t.Fatal("invalid credential change accepted")
		}
	}
	cipher, _ := secretstore.NewAESGCM("cloud-test", make([]byte, 32))
	encoded, _ := json.Marshal(old)
	ctx := context.Background()
	ciphertext, err := cipher.Encrypt(ctx, encoded, cloudAccountAAD("account-1"))
	if err != nil {
		t.Fatal(err)
	}
	svc := &AccessService{cloudCipher: cipher}
	decoded, err := svc.cloudCredentials(ctx, domain.CloudAccount{ID: "account-1", CredentialsCiphertext: ciphertext})
	if err != nil || decoded != old {
		t.Fatal("credential round trip failed")
	}
	if _, err := svc.cloudCredentials(ctx, domain.CloudAccount{ID: "account-2", CredentialsCiphertext: ciphertext}); err == nil {
		t.Fatal("credentials could be moved to another account")
	}
	if _, err := cipher.Decrypt(ctx, ciphertext, cloudTargetAAD("account-1")); err == nil {
		t.Fatal("target and credential encryption contexts collided")
	}
	public, _ := json.Marshal(domain.CloudAccount{ID: "account-1", CredentialsCiphertext: ciphertext})
	if strings.Contains(string(public), ciphertext) || strings.Contains(string(public), old.SecretKey) {
		t.Fatal("cloud account JSON exposed credentials")
	}
}

func TestCloudSnapshotScopeAndPrivateTargets(t *testing.T) {
	values := []cloudassets.Instance{{ID: "i-selected", Name: "mysql", Host: "10.0.0.1"}, {ID: "i-other", Host: "10.0.0.2"}, {ID: "i-no-ip"}}
	prepared, result, err := prepareCloudInstances(values, []string{"i-selected", "i-missing", "i-no-ip"})
	if err != nil || len(prepared) != 1 || prepared[0].ID != "i-selected" || result.Skipped != 1 || !slices.Equal(result.MissingIDs, []string{"i-missing"}) {
		t.Fatalf("scope: %+v %+v %v", prepared, result, err)
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "::1", "http://metadata", "10.0.0.1:3306"} {
		if _, _, err := prepareCloudInstances([]cloudassets.Instance{{ID: "i-1", Host: host}}, nil); err == nil {
			t.Fatalf("invalid discovered host accepted: %s", host)
		}
	}
	if _, _, err := prepareCloudInstances(append(values, values[0]), nil); err == nil {
		t.Fatal("duplicate identity accepted")
	}
}

func TestCloudSyncInputDoesNotBroadenInvalidFilters(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	input := domain.CloudSyncInput{RegionID: uuid, GatewayID: uuid, ApproverID: uuid, CloudRegion: " cn-hangzhou ",
		InstanceIDs: []string{"i-2", " i-1 ", "i-2"}, Ports: []int{3306, 22, 22}, RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 3600}
	if err := normalizeCloudSync(&input); err != nil || !slices.Equal(input.InstanceIDs, []string{"i-1", "i-2"}) || !slices.Equal(input.Ports, []int{22, 3306}) {
		t.Fatalf("normalize: %+v, %v", input, err)
	}
	input.InstanceIDs = []string{" "}
	if err := normalizeCloudSync(&input); !errors.Is(err, ErrValidation) {
		t.Fatal("blank ID became an unrestricted region sync")
	}
	if strings.Contains(cloudSyncError(errors.New("sensitive-db-error")), "sensitive-db-error") {
		t.Fatal("internal error leaked through job results")
	}
}

func TestSingleECSCloudSyncWithoutManualGatewayOrRegion(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	input := domain.CloudSyncInput{ApproverID: uuid, CloudRegion: "cn-hangzhou", InstanceIDs: []string{"i-only"}, Ports: []int{22}, RiskLevel: domain.RiskLevelNormal, MaxTTLSeconds: 3600}
	if err := normalizeCloudSync(&input); err != nil || input.RegionID != "" {
		t.Fatalf("automatic gateway and region rejected: %v", err)
	}
	values := []cloudassets.Instance{{ID: "i-only", Host: "10.0.0.1"}, {ID: "i-unselected", Host: "10.0.0.2"}}
	prepared, result, err := prepareCloudInstances(values, input.InstanceIDs)
	if err != nil || len(prepared) != 1 || prepared[0].ID != "i-only" || len(result.MissingIDs) != 0 {
		t.Fatalf("single-instance scope expanded: %+v %v", prepared, err)
	}
	input.InstanceIDs = []string{" "}
	if err := normalizeCloudSync(&input); !errors.Is(err, ErrValidation) {
		t.Fatal("blank instance ID broadened into region sync")
	}
}
