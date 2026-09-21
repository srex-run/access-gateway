//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

func TestAssetConfigurationUpdatesEncryptTargetsAndPreserveMetadata(t *testing.T) {
	database := openDatabase(t)
	ctx := context.Background()
	repos := newRepositories()
	admin, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Admin", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := repos.users.Create(ctx, database, domain.User{ID: id.New(), Nickname: "Reader", Status: domain.UserStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secretstore.NewAESGCM("test", []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	system, err := service.NewSystemSettingsService(database, cipher, "https://console.example.test")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.NewAccessService(service.ServiceOptions{
		DB: database, Users: repos.users, Regions: repos.regions, Gateways: repos.gateways, Assets: repos.assets,
		Requests: repos.requests, Approvals: repos.approvals, Sessions: repos.sessions, SessionEvents: repos.sessionEvents,
		Audits: repos.audits, Outbox: repos.outbox, Gateway: &sessionRuntimeStub{}, AssetEncryptor: cipher, SystemSettings: system, Logger: zerolog.Nop(),
		DefaultTTL: time.Hour, MaxTTL: time.Hour, AdminUserIDs: map[string]struct{}{admin.ID: {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := svc.CreateGateway(ctx, admin.ID, service.CreateGatewayInput{Name: "Local gateway"})
	if err != nil {
		t.Fatal(err)
	}
	original, err := svc.CreateAsset(ctx, admin.ID, service.CreateAssetInput{GatewayID: gw.ID, Name: "mysql", AssetType: "mysql", Target: "10.10.20.211", MaxTTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	port, err := svc.CreateAssetPort(ctx, admin.ID, original.ID, domain.AssetPort{Port: 33306, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	target := "127.0.0.1"
	updated, err := svc.UpdateAsset(ctx, admin.ID, original.ID, service.UpdateAssetInput{Target: &target})
	if err != nil {
		t.Fatal(err)
	}
	if updated.TargetCiphertext == original.TargetCiphertext || strings.Contains(updated.TargetCiphertext, target) {
		t.Fatal("updated target was not encrypted")
	}
	plaintext, err := cipher.Decrypt(ctx, updated.TargetCiphertext, []byte(original.ID))
	if err != nil || string(plaintext) != target {
		t.Fatal("updated target cannot be decrypted for its asset")
	}
	clear(plaintext)
	if _, err := cipher.Decrypt(ctx, updated.TargetCiphertext, []byte(id.New())); err == nil {
		t.Fatal("updated target can be decrypted with another asset identity")
	}
	expected := original
	expected.TargetCiphertext, expected.UpdatedAt = updated.TargetCiphertext, updated.UpdatedAt
	if !reflect.DeepEqual(updated, expected) {
		t.Fatal("target-only change overwrote asset configuration")
	}
	name, assetType, risk, ttl := " renamed ", " database ", domain.RiskLevelSensitive, 1800
	metadata := service.UpdateAssetInput{Name: &name, AssetType: &assetType, RiskLevel: &risk, MaxTTLSeconds: &ttl}
	updated, err = svc.UpdateAsset(ctx, admin.ID, original.ID, metadata)
	if err != nil || updated.TargetCiphertext != expected.TargetCiphertext || updated.Name != "renamed" || updated.AssetType != "database" || updated.RiskLevel != risk || updated.MaxTTLSeconds != ttl {
		t.Fatalf("metadata edit lost the target or submitted changes: %v", err)
	}
	ports, err := repos.assets.ListPorts(ctx, database, original.ID)
	if err != nil || len(ports) != 1 || ports[0].ID != port.ID || ports[0].Port != 33306 {
		t.Fatal("asset edit changed its allowed ports")
	}
	bindings, err := repos.gateways.ListAssetBindings(ctx, database, original.ID)
	if err != nil || len(bindings) != 1 || bindings[0].GatewayID != gw.ID {
		t.Fatal("asset edit changed gateway bindings")
	}
	if _, err := svc.UpdateAsset(ctx, reader.ID, original.ID, metadata); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("unprivileged asset update accepted: %v", err)
	}
	if _, err := svc.UpdateAsset(ctx, admin.ID, id.New(), metadata); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("missing asset error: %v", err)
	}
	blank, invalidRisk, badTTL := " ", domain.RiskLevel("invalid"), 18001
	longTarget, longName := strings.Repeat("a", 4097), strings.Repeat("a", 129)
	for _, invalid := range []struct {
		input   service.UpdateAssetInput
		message string
	}{
		{service.UpdateAssetInput{}, "请至少修改一项资产配置"},
		{service.UpdateAssetInput{Target: &blank}, "目标地址不能为空"},
		{service.UpdateAssetInput{Name: &blank}, "资产名称不能为空"},
		{service.UpdateAssetInput{AssetType: &blank}, "资产类型不能为空"},
		{service.UpdateAssetInput{Name: &longName}, "资产名称不能包含控制字符，且不能超过 128 个字符"},
		{service.UpdateAssetInput{Target: &longTarget}, "目标地址不能包含控制字符，且不能超过 4096 个字符"},
		{service.UpdateAssetInput{RiskLevel: &invalidRisk}, "请选择有效的风险级别"},
		{service.UpdateAssetInput{MaxTTLSeconds: &badTTL}, "最长访问时限必须在 1-18000 秒之间"},
	} {
		_, err := svc.UpdateAsset(ctx, admin.ID, original.ID, invalid.input)
		var validation *service.RequestValidationError
		if !errors.Is(err, service.ErrValidation) || !errors.As(err, &validation) || validation.Message != invalid.message {
			t.Fatalf("invalid edit did not return an actionable message: %v", err)
		}
	}
	unchanged, err := repos.assets.GetByID(ctx, database, original.ID)
	if err != nil || !reflect.DeepEqual(unchanged, updated) {
		t.Fatal("failed edit modified the asset")
	}
	events, err := repos.audits.List(ctx, database, domain.AuditFilter{AssetID: original.ID, EventType: "asset.updated", Limit: 10})
	if err != nil || len(events) != 2 {
		t.Fatalf("configuration audit missing: count=%d err=%v", len(events), err)
	}
	for _, event := range events {
		encoded, _ := json.Marshal(event)
		if workflowID, ok := event.Metadata["approval_workflow_id"]; !ok || workflowID != nil {
			t.Fatal("automatic workflow was not recorded as a JSON null")
		}
		if event.ActorID == nil || *event.ActorID != admin.ID || event.Metadata["changed_fields"] == nil || strings.Contains(string(encoded), target) || strings.Contains(string(encoded), updated.TargetCiphertext) {
			t.Fatal("configuration audit leaked a target or omitted the editor")
		}
		fields := event.Metadata["changed_fields"]
		if !reflect.DeepEqual(fields, []any{"target"}) && !reflect.DeepEqual(fields, []any{"name", "asset_type", "risk_level", "max_ttl_seconds"}) {
			t.Fatalf("configuration audit recorded incorrect fields: %v", fields)
		}
	}
	source, externalID, generation := "cloud.test", "instance-1", id.New()
	external := original
	external.ID, external.Name = id.New(), "external"
	external.AssetType = "ssh"
	external.ExternalSource, external.ExternalID, external.SyncGeneration = &source, &externalID, &generation
	external, err = repos.assets.UpsertExternal(ctx, database, external)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateAsset(ctx, admin.ID, external.ID, service.UpdateAssetInput{Target: &target})
	var validation *service.RequestValidationError
	if !errors.Is(err, service.ErrValidation) || !errors.As(err, &validation) || validation.Message != "该资产由外部来源同步，请在来源系统修改目标地址" {
		t.Fatalf("source-owned target did not return an actionable rejection: %v", err)
	}
	// The asset form also submits unchanged metadata when adding native tunnel
	// ports. Synced assets must accept this without target login credentials.
	nativePorts := &service.AssetAuditUpdate{Profiles: []settings.AuditProfile{
		{Name: "ssh-default", Protocol: "ssh", Port: 22},
		{Name: "ssh-extra", Protocol: "ssh", Port: 60022},
	}, Keys: map[string]settings.AuditKeyChanges{"ssh-default": {}, "ssh-extra": {}}}
	withPorts, err := svc.UpdateAsset(ctx, admin.ID, external.ID, service.UpdateAssetInput{
		Name: &external.Name, AssetType: &external.AssetType, RiskLevel: &external.RiskLevel,
		MaxTTLSeconds: &external.MaxTTLSeconds, Audit: nativePorts,
	})
	if err != nil {
		t.Fatalf("add native ports to synced asset: %v", err)
	}
	expectedExternal := external
	expectedExternal.UpdatedAt = withPorts.UpdatedAt
	if !reflect.DeepEqual(withPorts, expectedExternal) {
		t.Fatal("adding ports overwrote synced asset metadata or its encrypted target")
	}
	ports, err = repos.assets.ListPorts(ctx, database, external.ID)
	if err != nil || len(ports) != 2 || ports[0].Port != 22 || ports[1].Port != 60022 {
		t.Fatalf("native ports were not saved: %v %v", ports, err)
	}
	view, err := svc.GetAssetAudit(ctx, admin.ID, external.ID)
	if err != nil || view.Revision != 1 || len(view.Profiles) != 2 {
		t.Fatalf("native port configuration was not saved atomically: %v", err)
	}
	events, err = repos.audits.List(ctx, database, domain.AuditFilter{AssetID: external.ID, EventType: "asset.updated", Limit: 10})
	if err != nil || len(events) != 1 || !reflect.DeepEqual(events[0].Metadata["changed_fields"], []any{"audit"}) {
		t.Fatalf("native port edit did not produce its operation log: %v", err)
	}
	t.Run("port deletion", func(t *testing.T) {
		removed, remaining := ports[0], ports[1]
		if err := svc.DeleteAssetPort(ctx, reader.ID, external.ID, removed.ID); !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("ordinary user deleted an asset port: %v", err)
		}
		if err := svc.DeleteAssetPort(ctx, admin.ID, original.ID, removed.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("port was deleted through another asset: %v", err)
		}
		if err := svc.DeleteAssetPort(ctx, admin.ID, external.ID, removed.ID); err != nil {
			t.Fatal(err)
		}
		current, err := repos.assets.ListPorts(ctx, database, external.ID)
		if err != nil || len(current) != 1 || current[0].ID != remaining.ID {
			t.Fatalf("delete changed unrelated ports: %+v %v", current, err)
		}
		updatedAudit, err := svc.GetAssetAudit(ctx, admin.ID, external.ID)
		if err != nil || updatedAudit.Revision != view.Revision+1 || len(updatedAudit.Profiles) != 1 || updatedAudit.Profiles[0].Port != remaining.Port {
			t.Fatalf("deleted port remained in saved configuration: %+v %v", updatedAudit, err)
		}
		if _, err := svc.UpdateAsset(ctx, admin.ID, external.ID, service.UpdateAssetInput{Audit: &service.AssetAuditUpdate{Revision: view.Revision, Profiles: view.Profiles}}); !errors.Is(err, service.ErrStateConflict) {
			t.Fatalf("stale asset form restored deleted port: %v", err)
		}
		if err := svc.DeleteAssetPort(ctx, admin.ID, external.ID, removed.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("repeat delete did not report a missing port: %v", err)
		}
		if err := svc.DeleteAssetPort(ctx, admin.ID, external.ID, remaining.ID); err != nil {
			t.Fatalf("delete final port: %v", err)
		}
		empty, err := svc.GetAssetAudit(ctx, admin.ID, external.ID)
		if err != nil || len(empty.Profiles) != 0 || len(empty.HasSecrets) != 0 {
			t.Fatalf("final port left configuration or credentials: %+v %v", empty, err)
		}
		current, err = repos.assets.ListPorts(ctx, database, external.ID)
		if err != nil || len(current) != 0 {
			t.Fatalf("deleted ports still offered for access: %+v %v", current, err)
		}
		readded, err := svc.CreateAssetPort(ctx, admin.ID, external.ID, domain.AssetPort{Port: removed.Port, Protocol: removed.Protocol})
		if err != nil || readded.ID == removed.ID {
			t.Fatalf("deleted port could not be added again: %+v %v", readded, err)
		}
		deletedEvents, err := repos.audits.List(ctx, database, domain.AuditFilter{AssetID: external.ID, EventType: "asset_port.deleted", Limit: 10})
		if err != nil || len(deletedEvents) != 2 {
			t.Fatalf("missing port deletion audit: count=%d err=%v", len(deletedEvents), err)
		}
	})
}
