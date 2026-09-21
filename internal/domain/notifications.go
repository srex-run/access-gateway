package domain

import "time"

type Notification struct {
	ID        string     `json:"id"`
	UserID    string     `json:"-"`
	EventType string     `json:"event_type"`
	DedupeKey string     `json:"-"`
	Title     string     `json:"title"`
	Content   string     `json:"content"`
	RequestID string     `json:"request_id"`
	SessionID *string    `json:"session_id,omitempty"`
	ReadAt    *time.Time `json:"read_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type NotificationPage struct {
	Items       []Notification `json:"items"`
	UnreadCount int64          `json:"unread_count"`
	HasMore     bool           `json:"has_more"`
}
