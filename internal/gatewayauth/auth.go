package gatewayauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

type Mode string

const (
	ModeShared     Mode = "shared"
	ModeTransition Mode = "transition"
	ModePerGateway Mode = "per_gateway"
)

func ParseMode(value string) (Mode, error) {
	mode := Mode(strings.TrimSpace(value))
	if mode == "" {
		mode = ModeShared
	}
	switch mode {
	case ModeShared, ModeTransition, ModePerGateway:
		return mode, nil
	default:
		return "", fmt.Errorf("gateway audit authentication mode is invalid")
	}
}

type Authenticator interface {
	Authenticate(context.Context, string, string) (bool, error)
}

type GatewayLookup func(context.Context, string) (domain.Gateway, error)

type CredentialAuthenticator struct {
	lookup   GatewayLookup
	resolver secretstore.CredentialResolver
}

func NewCredentialAuthenticator(lookup GatewayLookup, resolver secretstore.CredentialResolver) (*CredentialAuthenticator, error) {
	if lookup == nil || resolver == nil {
		return nil, fmt.Errorf("gateway credential authenticator requires a gateway lookup and credential resolver")
	}
	return &CredentialAuthenticator{lookup: lookup, resolver: resolver}, nil
}

func (a *CredentialAuthenticator) Authenticate(ctx context.Context, gatewayID, presented string) (bool, error) {
	gatewayID = strings.TrimSpace(gatewayID)
	if !id.IsUUID(gatewayID) || secretstore.ValidateCredential([]byte(presented)) != nil {
		return false, nil
	}
	gatewayRecord, err := a.lookup(ctx, gatewayID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load gateway credential reference: %w", err)
	}
	if gatewayRecord.ID != gatewayID {
		return false, fmt.Errorf("gateway credential lookup returned a mismatched gateway")
	}
	if gatewayRecord.AuthSecretRef == nil {
		return false, nil
	}
	credentials, err := a.resolver.Resolve(ctx, *gatewayRecord.AuthSecretRef)
	defer clearCredentialBytes(credentials)
	if err != nil {
		// A resolver error may contain the database-backed reference or its file
		// path. The HTTP boundary logs this error, so keep the cause opaque.
		return false, fmt.Errorf("resolve gateway credential")
	}
	presentedHash := sha256.Sum256([]byte(presented))
	matched := 0
	for _, credential := range credentials {
		if err := secretstore.ValidateCredential(credential); err != nil {
			return false, fmt.Errorf("gateway credential is invalid: %w", err)
		}
		expectedHash := sha256.Sum256(credential)
		matched |= subtle.ConstantTimeCompare(presentedHash[:], expectedHash[:])
	}
	return matched == 1, nil
}

func clearCredentialBytes(values [][]byte) {
	for _, value := range values {
		clear(value)
	}
}
