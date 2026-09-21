package realtime

import "sync"

// Change is internal routing metadata. Only Topic is sent to the browser.
type Change struct {
	Schema     string `json:"schema"`
	Topic      string `json:"topic"`
	UserID     string `json:"user_id"`
	Permission string `json:"permission"`
}

type subscription struct {
	userID string
	events chan Change
}

type Hub struct {
	mu        sync.Mutex
	available bool
	clients   map[*subscription]struct{}
}

func NewHub() *Hub {
	return &Hub{available: true, clients: make(map[*subscription]struct{})}
}

// Subscribe must happen before loading permissions, so a concurrent role
// change is queued and forces the stream to authenticate again.
func (h *Hub) Subscribe(userID string) (<-chan Change, func(), bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.available {
		return nil, func() {}, false
	}
	s := &subscription{userID: userID, events: make(chan Change, 32)}
	h.clients[s] = struct{}{}
	return s.events, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, exists := h.clients[s]; exists {
			delete(h.clients, s)
			close(s.events)
		}
	}, true
}

func (h *Hub) Publish(change Change) {
	switch change.Topic {
	case "notifications", "requests", "sessions", "cloud", "settings", "catalog", "audit", "identity":
	default:
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.clients {
		if change.UserID != "" && change.UserID != s.userID {
			continue
		}
		select {
		case s.events <- change:
		default:
			// A slow client reconnects and reloads a snapshot instead of losing
			// updates or holding up database delivery to other clients.
			delete(h.clients, s)
			close(s.events)
		}
	}
}

func (h *Hub) setAvailable(available bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.available = available
	if !available {
		for s := range h.clients {
			delete(h.clients, s)
			close(s.events)
		}
	}
}
