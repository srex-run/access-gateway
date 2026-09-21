package repository

import (
	"context"

	"github.com/srex-run/access-gateway/internal/domain"
)

type NotificationRepository struct{}

// Repeated outbox scheduling for an unfinished quorum must not duplicate a
// notification or reset its read state.
func (NotificationRepository) Append(ctx context.Context, q DBTX, v domain.Notification) error {
	const query = `INSERT INTO user_notifications (id, user_id, event_type, dedupe_key, title, content, request_id, session_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (user_id, dedupe_key) DO NOTHING`
	result, err := q.ExecContext(ctx, query, v.ID, v.UserID, v.EventType, v.DedupeKey, v.Title, v.Content, v.RequestID, v.SessionID)
	if err != nil {
		return opError("append notification", err)
	}
	_, err = result.RowsAffected() // Zero is the expected idempotent duplicate.
	return opError("append notification", err)
}

func (NotificationRepository) List(ctx context.Context, q DBTX, userID string, limit, offset int) ([]domain.Notification, error) {
	if limit < 1 || limit > 101 {
		limit = 101
	}
	if offset < 0 {
		offset = 0
	}
	const query = `SELECT ` + notificationColumns + ` FROM user_notifications
		WHERE user_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`
	rows, err := q.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, opError("list notifications", err)
	}
	values, err := CollectRows(rows, scanNotification)
	return values, opError("list notifications", err)
}

func (NotificationRepository) CountUnread(ctx context.Context, q DBTX, userID string) (int64, error) {
	const query = `SELECT count(*) FROM user_notifications WHERE user_id=$1 AND read_at IS NULL`
	count, err := scanNotificationCount(q.QueryRowContext(ctx, query, userID))
	return count, opError("count unread notifications", err)
}

func (NotificationRepository) MarkRead(ctx context.Context, q DBTX, userID, notificationID string) error {
	const query = `UPDATE user_notifications SET read_at=COALESCE(read_at, NOW()) WHERE user_id=$1 AND id=$2`
	result, err := q.ExecContext(ctx, query, userID, notificationID)
	if err != nil {
		return opError("mark notification read", err)
	}
	return affected("mark notification read", result)
}

func (NotificationRepository) MarkAllRead(ctx context.Context, q DBTX, userID string) error {
	const query = `UPDATE user_notifications SET read_at=NOW() WHERE user_id=$1 AND read_at IS NULL`
	result, err := q.ExecContext(ctx, query, userID)
	if err != nil {
		return opError("mark all notifications read", err)
	}
	_, err = result.RowsAffected() // Empty inboxes are already read.
	return opError("mark all notifications read", err)
}
