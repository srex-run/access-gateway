package service

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/securetransport"
)

type BrowserTransportService struct {
	db     *sql.DB
	cipher secretstore.Cipher
	repo   repository.TransportRepository
	keyMu  sync.Mutex
}

func NewBrowserTransportService(db *sql.DB, cipher secretstore.Cipher) (*BrowserTransportService, error) {
	if db == nil || cipher == nil {
		return nil, fmt.Errorf("browser transport requires database and key encryption")
	}
	return &BrowserTransportService{db: db, cipher: cipher}, nil
}

func transportKeyAAD(id string) []byte {
	return []byte("access-gateway/browser-transport-key/v1/" + id)
}

func (s *BrowserTransportService) activeKey(ctx context.Context) (repository.TransportKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	key, err := s.repo.ActiveKey(ctx, s.db)
	if !errors.Is(err, repository.ErrNotFound) {
		return key, err
	}
	private, public, err := securetransport.GenerateKey()
	if err != nil {
		return key, err
	}
	der := x509.MarshalPKCS1PrivateKey(private)
	defer clear(der)
	key.ID, key.PublicKey = id.New(), public
	key.PrivateKeyCiphertext, err = s.cipher.Encrypt(ctx, der, transportKeyAAD(key.ID))
	if err != nil {
		return key, err
	}
	// RSA generation stays outside the transaction. Recheck under a shared lock
	// so concurrent replicas converge on the same active key.
	err = InTx(ctx, s.db, func(q repository.DBTX) error {
		if err := s.repo.LockKeyRotation(ctx, q); err != nil {
			return err
		}
		current, err := s.repo.ActiveKey(ctx, q)
		if err == nil {
			key = current
			return nil
		}
		if !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		return s.repo.CreateKey(ctx, q, key)
	})
	return key, err
}

func (s *BrowserTransportService) Create(ctx context.Context, binding securetransport.Binding) (securetransport.Challenge, error) {
	key, err := s.activeKey(ctx)
	if err != nil {
		return securetransport.Challenge{}, err
	}
	c, err := s.repo.CreateChallenge(ctx, s.db, securetransport.Challenge{ID: id.New(), KeyID: key.ID, Binding: binding})
	c.PublicKey, c.Algorithm = key.PublicKey, securetransport.Algorithm
	return c, err
}

func (s *BrowserTransportService) Open(ctx context.Context, binding securetransport.Binding, request securetransport.Request) ([]byte, *securetransport.Reply, error) {
	if !id.IsUUID(request.ChallengeID) {
		return nil, nil, securetransport.ErrInvalid
	}
	c, key, err := s.repo.Consume(ctx, s.db, request.ChallengeID, binding)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil, securetransport.ErrInvalid
	}
	if err != nil {
		return nil, nil, err
	}
	der, err := s.cipher.Decrypt(ctx, key.PrivateKeyCiphertext, transportKeyAAD(key.ID))
	if err != nil {
		return nil, nil, fmt.Errorf("open browser transport key: %w", ErrNotConfigured)
	}
	defer clear(der)
	private, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse browser transport key: %w", ErrNotConfigured)
	}
	return securetransport.Open(private, c, request.Envelope)
}
