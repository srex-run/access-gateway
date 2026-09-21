package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/authz"
	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/service"
)

type accessSetupBackend struct {
	backendStub
	UserDirectoryService
	testCalls, requestCalls, userCalls, listLimit int
}

func (s *accessSetupBackend) CreateTestAccessRequest(_ context.Context, input service.CreateRequestInput) (domain.AccessRequest, error) {
	s.testCalls++
	return domain.AccessRequest{ID: testSessionID, ApprovalMode: "admin_test", ApplicantID: input.ApplicantID, Status: domain.AccessRequestApproved}, nil
}
func (s *accessSetupBackend) CreateAccessRequest(context.Context, service.CreateRequestInput) (domain.AccessRequest, error) {
	s.requestCalls++
	return domain.AccessRequest{ID: testSessionID, ApprovalMode: "required", Status: domain.AccessRequestPendingApproval}, nil
}
func (s *accessSetupBackend) ListMyAccessRequests(_ context.Context, _ string, limit, _ int) ([]domain.AccessRequest, error) {
	s.listLimit = limit
	return []domain.AccessRequest{}, nil
}
func (s *accessSetupBackend) ListUsers(context.Context, string, string, bool, int, int) ([]repository.UserSummary, error) {
	s.userCalls++
	return []repository.UserSummary{{ID: testUserID, Nickname: "Approver", Username: "approver", Status: "active"}}, nil
}
func (s *accessSetupBackend) CreateLocalUser(_ context.Context, _ string, input service.CreateLocalUserInput) (repository.UserSummary, error) {
	s.userCalls++
	return repository.UserSummary{ID: testUserID, Nickname: input.Nickname, Username: input.Username, Status: "active"}, nil
}

func TestAccessSetupPermissionsAndApprovalIsolation(t *testing.T) {
	for _, item := range []struct {
		method, path string
		permission   authz.Permission
	}{
		{"POST", "/api/v1/admin/access-tests", authz.PermissionRoleManage},
		{"POST", "/api/v1/admin/users", authz.PermissionUserManage},
		{"GET", "/api/v1/admin/users", authz.PermissionUserRead},
		{"PATCH", "/api/v1/admin/users/" + testUserID, authz.PermissionUserManage},
		{"POST", "/api/v1/admin/role-bindings", authz.PermissionRoleManage},
		{"POST", "/api/v1/admin/roles", authz.PermissionRoleManage},
		{"GET", "/api/v1/admin/permissions", authz.PermissionRoleManage},
		{"POST", "/api/v1/admin/workflows", authz.PermissionWorkflowManage},
		{"POST", "/api/v1/admin/ownerships", authz.PermissionWorkflowManage},
		{"PATCH", "/api/v1/admin/assets/" + testUserID + "/labels", authz.PermissionWorkflowManage},
		{"GET", "/api/v1/admin/assets/" + testUserID + "/approvers", authz.PermissionCatalogManage},
		{"GET", "/api/v1/assets/" + testUserID + "/approvers", authz.PermissionDirectoryRead},
	} {
		permission, protected := routePermission(item.method, item.path)
		if !protected || permission != item.permission {
			t.Fatalf("wrong permission for %s: %s", item.path, permission)
		}
	}
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &accessSetupBackend{}
	server.Service = backend
	for _, sample := range []struct {
		path, body string
		denied     bool
		status     int
	}{
		{"/admin/access-tests", `{}`, true, 403},
		{"/admin/access-tests", `{}`, false, 201},
		{"/access-requests", `{"approval_mode":"admin_test"}`, false, 400},
		{"/access-requests", `{"skip_approval":true}`, false, 400},
		{"/access-requests", `{}`, false, 201},
	} {
		backend.authorizeErr = nil
		if sample.denied {
			backend.authorizeErr = service.ErrForbidden
		}
		request := httptest.NewRequest("POST", "http://console.test/api/v1"+sample.path, strings.NewReader(sample.body))
		request.Header.Set("X-User-ID", testUserID)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://console.test")
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		if response.Code != sample.status {
			t.Fatalf("%s: %d; want %d", sample.path, response.Code, sample.status)
		}
	}
	if backend.testCalls != 1 || backend.requestCalls != 1 {
		t.Fatal("approval boundary was bypassed")
	}
}

func TestAccessRequestListAcceptsLookaheadPage(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &accessSetupBackend{}
	server.Service = backend
	request := httptest.NewRequest("GET", "http://console.test/api/v1/access-requests?limit=51&offset=0", nil)
	request.Header.Set("X-User-ID", testUserID)
	response := httptest.NewRecorder()
	server.Container().ServeHTTP(response, request)
	if response.Code != 200 || backend.listLimit != 51 {
		t.Fatalf("50-row page lookahead failed: %d / %d", response.Code, backend.listLimit)
	}
}

func TestAccessSetupAccountCreationRequiresEncryption(t *testing.T) {
	server := newAuthServer(t, &accountStub{}, &attemptStub{true}, &loginStateMemory{}, &redirectStub{})
	server.AllowDevAuth = true
	backend := &accessSetupBackend{}
	server.Service = backend
	const body = `{"nickname":"Approver","username":"approver","password":"private-password"}`
	for _, encrypted := range []bool{false, true} {
		request := httptest.NewRequest("POST", "http://console.test/api/v1/admin/users", strings.NewReader(body))
		request.Header.Set("X-User-ID", testUserID)
		request.Header.Set("Origin", "http://console.test")
		request.Header.Set("Content-Type", "application/json")
		if encrypted {
			encryptTestRequest(t, server, request, body)
		}
		response := httptest.NewRecorder()
		server.Container().ServeHTTP(response, request)
		want := http.StatusBadRequest
		if encrypted {
			want = http.StatusCreated
		}
		if response.Code != want || strings.Contains(response.Body.String(), "private-password") {
			t.Fatalf("account encryption: status=%d", response.Code)
		}
	}
	if backend.userCalls != 1 {
		t.Fatal("plaintext password reached account creation")
	}
}
