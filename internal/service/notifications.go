package service

import (
	"context"
	"fmt"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
)

func (s *AccessService) ListNotifications(ctx context.Context, userID string, limit, offset int) (domain.NotificationPage, error) {
	if err := s.CheckActiveUser(ctx, userID); err != nil {
		return domain.NotificationPage{}, err
	}
	if limit < 1 || limit > 100 || offset < 0 {
		return domain.NotificationPage{}, ErrValidation
	}
	repo := repository.NotificationRepository{}
	items, err := repo.List(ctx, s.db, userID, limit+1, offset)
	if err != nil {
		return domain.NotificationPage{}, err
	}
	count, err := repo.CountUnread(ctx, s.db, userID)
	page := domain.NotificationPage{Items: items, UnreadCount: count, HasMore: len(items) > limit}
	if page.HasMore {
		page.Items = items[:limit]
	}
	return page, err
}

func (s *AccessService) MarkNotificationRead(ctx context.Context, userID, notificationID string) error {
	if err := s.CheckActiveUser(ctx, userID); err != nil {
		return err
	}
	if err := validateUUID(notificationID, "notification ID"); err != nil {
		return err
	}
	return (repository.NotificationRepository{}).MarkRead(ctx, s.db, userID, notificationID)
}

func (s *AccessService) MarkAllNotificationsRead(ctx context.Context, userID string) error {
	if err := s.CheckActiveUser(ctx, userID); err != nil {
		return err
	}
	return (repository.NotificationRepository{}).MarkAllRead(ctx, s.db, userID)
}

// Called in the same transaction as the business transition and outbox event.
// Feishu availability and delivery retries cannot delay or duplicate the inbox.
func (s *AccessService) appendInAppNotifications(ctx context.Context, q repository.DBTX, eventType, aggregateID string) error {
	var request domain.AccessRequest
	var session domain.Session
	var err error
	switch eventType {
	case outboxNotifyApproval, outboxNotifyRequestResult:
		request, err = s.requests.GetByID(ctx, q, aggregateID)
	case outboxNotifySessionReady, outboxNotifySessionClosed:
		session, err = s.sessions.GetByID(ctx, q, aggregateID)
		if err == nil {
			request, err = s.requests.GetByID(ctx, q, session.RequestID)
		}
	default:
		return nil
	}
	if err != nil {
		return err
	}
	asset, err := s.assets.GetIncludingDeleted(ctx, q, request.AssetID)
	if err != nil {
		return err
	}
	var approvals []domain.Approval
	if eventType == outboxNotifyApproval {
		approvals, err = s.approvals.ListByRequest(ctx, q, request.ID)
		if err != nil {
			return err
		}
	}
	for _, notice := range requestNotifications(eventType, request, session, asset.Name, approvals) {
		if err := (repository.NotificationRepository{}).Append(ctx, q, notice); err != nil {
			return err
		}
	}
	return nil
}

func requestNotifications(eventType string, request domain.AccessRequest, session domain.Session, assetName string, approvals []domain.Approval) []domain.Notification {
	if request.ApprovalMode == "admin_test" {
		return nil
	}
	base := domain.Notification{UserID: request.ApplicantID, RequestID: request.ID}
	switch eventType {
	case outboxNotifyApproval:
		if request.Status != domain.AccessRequestPendingApproval {
			return nil
		}
		level, complete := nextApprovalLevel(approvals)
		if complete {
			return nil
		}
		notices := []domain.Notification{}
		for _, approval := range approvals {
			if approval.ApprovalLevel != level || approval.Decision != nil || approval.ApproverID == request.ApplicantID {
				continue
			}
			notice := base
			notice.ID, notice.UserID = id.New(), approval.ApproverID
			notice.EventType, notice.DedupeKey = "approval_requested", "approval:"+approval.ID
			notice.Title = "有访问申请待你审批"
			if request.Emergency {
				notice.Title = "紧急访问申请待你审批"
			}
			step := approval.StepName
			if step == "" {
				step = fmt.Sprintf("第 %d 级审批", level)
			}
			notice.Content = fmt.Sprintf("%s 的访问申请已到「%s」节点，请及时处理。", assetName, step)
			notices = append(notices, notice)
		}
		return notices
	case outboxNotifyRequestResult:
		result := map[domain.AccessRequestStatus]string{
			domain.AccessRequestApproved: "已通过", domain.AccessRequestRejected: "已拒绝",
			domain.AccessRequestCancelled: "已取消", domain.AccessRequestApprovalExpired: "审批已超时",
		}[request.Status]
		if result == "" {
			return nil
		}
		base.EventType, base.DedupeKey = "request_result", "request:"+request.ID+":"+string(request.Status)
		base.Title, base.Content = "访问申请"+result, fmt.Sprintf("你对 %s 的访问申请%s。", assetName, result)
	case outboxNotifySessionReady:
		if session.Status != domain.SessionRunning {
			return nil
		}
		base.EventType, base.DedupeKey = "session_ready", "session:"+session.ID+":ready"
		base.Title, base.Content = "访问会话已就绪", fmt.Sprintf("%s 的访问会话已就绪，可查看连接信息。", assetName)
		base.SessionID = &session.ID
	case outboxNotifySessionClosed:
		base.EventType, base.DedupeKey = "session_closed", "session:"+session.ID+":closed"
		base.Title, base.Content = "访问会话已结束", fmt.Sprintf("%s 的访问会话已结束。", assetName)
		base.SessionID = &session.ID
	default:
		return nil
	}
	base.ID = id.New()
	return []domain.Notification{base}
}
