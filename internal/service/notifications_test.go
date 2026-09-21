package service

import (
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
)

func TestNotificationsFollowCurrentApprovalLevel(t *testing.T) {
	request := domain.AccessRequest{ID: "request", ApplicantID: "applicant", Status: domain.AccessRequestPendingApproval, Emergency: true}
	approvals := []domain.Approval{
		{ID: "a", ApproverID: "first", ApprovalLevel: 1, RequiredApprovals: 2, StepName: "资源负责人"},
		{ID: "b", ApproverID: "second", ApprovalLevel: 1, RequiredApprovals: 2, StepName: "资源负责人"},
		{ID: "c", ApproverID: "platform", ApprovalLevel: 2, RequiredApprovals: 1, StepName: "平台管理"},
	}
	first := requestNotifications(outboxNotifyApproval, request, domain.Session{}, "生产数据库", approvals)
	if len(first) != 2 || first[0].UserID != "first" || first[1].UserID != "second" || first[0].DedupeKey != "approval:a" || !strings.Contains(first[0].Title, "紧急") || !strings.Contains(first[0].Content, "资源负责人") {
		t.Fatalf("wrong first recipients: %+v", first)
	}
	approved := domain.ApprovalApproved
	approvals[0].Decision = &approved
	partial := requestNotifications(outboxNotifyApproval, request, domain.Session{}, "生产数据库", approvals)
	if len(partial) != 1 || partial[0].UserID != "second" || partial[0].DedupeKey != first[1].DedupeKey {
		t.Fatalf("partial quorum duplicated or advanced notification: %+v", partial)
	}
	approvals[1].Decision = &approved
	next := requestNotifications(outboxNotifyApproval, request, domain.Session{}, "生产数据库", approvals)
	if len(next) != 1 || next[0].UserID != "platform" || !strings.Contains(next[0].Content, "平台管理") {
		t.Fatalf("next level did not receive notification: %+v", next)
	}
	approvals[2].ApproverID = request.ApplicantID
	if notices := requestNotifications(outboxNotifyApproval, request, domain.Session{}, "DB", approvals); len(notices) != 0 {
		t.Fatal("applicant received their own approval task")
	}
	request.Status = domain.AccessRequestRejected
	if notices := requestNotifications(outboxNotifyApproval, request, domain.Session{}, "DB", approvals); len(notices) != 0 {
		t.Fatal("finished request generated pending approval notification")
	}
}

func TestNotificationsSkipAdministratorTests(t *testing.T) {
	for _, event := range []string{outboxNotifyApproval, outboxNotifyRequestResult, outboxNotifySessionReady, outboxNotifySessionClosed} {
		t.Run(event, func(t *testing.T) {
			request := domain.AccessRequest{ID: "request", ApplicantID: "admin", ApprovalMode: "required", Status: domain.AccessRequestApproved}
			if event == outboxNotifyApproval {
				request.Status = domain.AccessRequestPendingApproval
			}
			session := domain.Session{ID: "session", Status: domain.SessionRunning}
			approvals := []domain.Approval{{ID: "approval", ApproverID: "approver", ApprovalLevel: 1, RequiredApprovals: 1}}
			if notices := requestNotifications(event, request, session, "DB", approvals); len(notices) != 1 {
				t.Fatalf("ordinary administrator request lost its notification: %+v", notices)
			}
			request.ApprovalMode = "admin_test"
			if notices := requestNotifications(event, request, session, "DB", approvals); len(notices) != 0 {
				t.Fatalf("administrator test generated notifications: %+v", notices)
			}
		})
	}
}

func TestNotificationsDeliverResultsAndSessionsToApplicant(t *testing.T) {
	for _, status := range []domain.AccessRequestStatus{domain.AccessRequestApproved, domain.AccessRequestRejected, domain.AccessRequestCancelled, domain.AccessRequestApprovalExpired} {
		request := domain.AccessRequest{ID: "request", ApplicantID: "applicant", Status: status}
		notices := requestNotifications(outboxNotifyRequestResult, request, domain.Session{}, "DB", nil)
		if len(notices) != 1 || notices[0].UserID != request.ApplicantID || notices[0].RequestID != request.ID || notices[0].SessionID != nil || notices[0].EventType != "request_result" || !strings.HasSuffix(notices[0].DedupeKey, string(status)) {
			t.Fatalf("wrong result notification for %s: %+v", status, notices)
		}
	}
	request := domain.AccessRequest{ID: "request", ApplicantID: "applicant", Status: domain.AccessRequestApproved}
	session := domain.Session{ID: "session", Status: domain.SessionRunning}
	for _, event := range []string{outboxNotifySessionReady, outboxNotifySessionClosed} {
		notices := requestNotifications(event, request, session, "DB", nil)
		if len(notices) != 1 || notices[0].UserID != request.ApplicantID || notices[0].SessionID == nil || *notices[0].SessionID != session.ID {
			t.Fatalf("wrong session notification: %+v", notices)
		}
	}
	session.Status = domain.SessionProvisioning
	if notices := requestNotifications(outboxNotifySessionReady, request, session, "DB", nil); len(notices) != 0 {
		t.Fatal("session ready was announced before running")
	}
}
