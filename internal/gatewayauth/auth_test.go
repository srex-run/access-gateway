package gatewayauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/domain"
	"github.com/srex-run/access-gateway/internal/repository"
)

type credentialResolverStub struct {
	credentials [][]byte
	err         error
	resolved    *[][]byte
}

func (s credentialResolverStub) Resolve(context.Context, string) ([][]byte, error) {
	values := make([][]byte, 0, len(s.credentials))
	for _, value := range s.credentials {
		values = append(values, append([]byte(nil), value...))
	}
	if s.resolved != nil {
		*s.resolved = values
	}
	return values, s.err
}

func TestCredentialAuthenticatorAcceptsCurrentAndPreviousCredentials(t *testing.T) {
	ref := "gateway-cn-east-1"
	authenticator, err := NewCredentialAuthenticator(func(_ context.Context, gatewayID string) (domain.Gateway, error) {
		return domain.Gateway{ID: gatewayID, AuthSecretRef: &ref}, nil
	}, credentialResolverStub{credentials: [][]byte{
		[]byte("current-0123456789abcdef0123456789"),
		[]byte("previous-0123456789abcdef01234567"),
	}})
	if err != nil {
		t.Fatalf("NewCredentialAuthenticator: %v", err)
	}
	for _, credential := range []string{"current-0123456789abcdef0123456789", "previous-0123456789abcdef01234567"} {
		accepted, authErr := authenticator.Authenticate(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", credential)
		if authErr != nil || !accepted {
			t.Fatalf("Authenticate(%q) = %v, %v", credential, accepted, authErr)
		}
	}
	accepted, authErr := authenticator.Authenticate(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "wrong---0123456789abcdef0123456789")
	if authErr != nil || accepted {
		t.Fatalf("wrong credential accepted=%v err=%v", accepted, authErr)
	}
}

func TestCredentialAuthenticatorFailsClosed(t *testing.T) {
	ref := "gateway-cn-east-1"
	tests := []struct {
		name       string
		gateway    domain.Gateway
		lookupErr  error
		resolveErr error
		wantErr    bool
		forbid     string
	}{
		{name: "unknown gateway", lookupErr: repository.ErrNotFound},
		{name: "missing reference", gateway: domain.Gateway{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}},
		{name: "lookup unavailable", lookupErr: errors.New("database unavailable"), wantErr: true},
		{name: "resolver unavailable", gateway: domain.Gateway{ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AuthSecretRef: &ref}, resolveErr: errors.New("secret unavailable: " + ref), wantErr: true, forbid: ref},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator, err := NewCredentialAuthenticator(func(context.Context, string) (domain.Gateway, error) {
				return test.gateway, test.lookupErr
			}, credentialResolverStub{credentials: [][]byte{[]byte("current-0123456789abcdef0123456789")}, err: test.resolveErr})
			if err != nil {
				t.Fatalf("NewCredentialAuthenticator: %v", err)
			}
			accepted, authErr := authenticator.Authenticate(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "current-0123456789abcdef0123456789")
			if accepted || (authErr != nil) != test.wantErr {
				t.Fatalf("Authenticate accepted=%v err=%v", accepted, authErr)
			}
			if authErr != nil && test.forbid != "" && strings.Contains(authErr.Error(), test.forbid) {
				t.Fatalf("Authenticate error leaked credential reference: %v", authErr)
			}
		})
	}
}

func TestCredentialAuthenticatorClearsPartialCredentialsOnResolverError(t *testing.T) {
	ref := "gateway-cn-east-1"
	var resolved [][]byte
	authenticator, err := NewCredentialAuthenticator(func(_ context.Context, gatewayID string) (domain.Gateway, error) {
		return domain.Gateway{ID: gatewayID, AuthSecretRef: &ref}, nil
	}, credentialResolverStub{
		credentials: [][]byte{[]byte("current-0123456789abcdef0123456789")},
		err:         errors.New("partial read failed"),
		resolved:    &resolved,
	})
	if err != nil {
		t.Fatalf("NewCredentialAuthenticator: %v", err)
	}
	if accepted, authErr := authenticator.Authenticate(context.Background(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "current-0123456789abcdef0123456789"); authErr == nil || accepted {
		t.Fatalf("Authenticate accepted=%v err=%v", accepted, authErr)
	}
	for _, credential := range resolved {
		for _, value := range credential {
			if value != 0 {
				t.Fatal("partial resolver credential was not cleared")
			}
		}
	}
}
