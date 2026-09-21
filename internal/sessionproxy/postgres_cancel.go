package sessionproxy

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

// CancelRequest has no account or TLS identity in libpq 16. Only the isolated
// web client's connections share this registry, and only while the authenticated
// connection that supplied BackendKeyData is alive. It is never shared between
// browser terminals or enabled on public client endpoints.
type postgresCancelRegistry struct {
	mu      sync.Mutex
	entries map[[8]byte]*Binding
}

func (s *postgresCancelRegistry) register(key [8]byte, binding Binding) func() {
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[[8]byte]*Binding)
	}
	s.entries[key] = &binding
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.entries[key] == &binding {
			delete(s.entries, key)
		}
	}
}

func (s *postgresCancelRegistry) lookup(packet []byte, binding Binding) (Binding, error) {
	if s == nil || len(packet) != 16 || binary.BigEndian.Uint32(packet) != 16 || binary.BigEndian.Uint32(packet[4:]) != 80877102 {
		return Binding{}, ErrProtocol
	}
	var key [8]byte
	copy(key[:], packet[8:])
	s.mu.Lock()
	defer s.mu.Unlock()
	owner := s.entries[key]
	if owner == nil || owner.Account != binding.Account || owner.AssetID != binding.AssetID || owner.TargetHost != binding.TargetHost || owner.TargetPort != binding.TargetPort {
		return Binding{}, ErrIdentity
	}
	return *owner, nil
}

// A nil back config means the connection has already completed its TLS upgrade.
// Plaintext local cancel packets still use verified TLS to the target database.
func servePostgresCancel(packet []byte, backend net.Conn, back *tls.Config, r *recorder, cancels *postgresCancelRegistry) error {
	owner, err := cancels.lookup(packet, r.binding)
	if err != nil {
		return err
	}
	op, err := r.begin(owner.Account, "cancel", "CANCEL", "", map[string]any{"query_connection_id": owner.ConnectionID})
	if err != nil {
		return err
	}
	err = func() error {
		if back != nil {
			if err := writeAll(backend, []byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
				return err
			}
			var answer [1]byte
			if _, err := io.ReadFull(backend, answer[:]); err != nil {
				return err
			}
			if answer[0] != 'S' {
				return ErrProtocol
			}
			secure := tls.Client(backend, back)
			if err := secure.HandshakeContext(r.ctx); err != nil {
				return fmt.Errorf("%w: %w", ErrTargetTLS, err)
			}
			backend = secure
		}
		if _, err := cancels.lookup(packet, r.binding); err != nil {
			return err
		}
		if err := writeAll(backend, packet); err != nil {
			return err
		}
		// PostgreSQL acknowledges a cancellation request by closing this extra
		// connection. Query errors and ReadyForQuery arrive on the main one.
		var reply [1]byte
		if _, err := io.ReadFull(backend, reply[:]); err != io.EOF {
			if err != nil {
				return err
			}
			return ErrProtocol
		}
		return nil
	}()
	result := "sent"
	if err != nil {
		result = "failure"
	}
	return errors.Join(err, op.end(result))
}
