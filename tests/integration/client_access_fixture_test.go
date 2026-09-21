//go:build integration

package integration_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/repository"
	"github.com/srex-run/access-gateway/internal/secretstore"
	"github.com/srex-run/access-gateway/internal/service"
	"github.com/srex-run/access-gateway/internal/settings"
)

// Existing TCP integration scenarios explicitly opt into client access. New
// installations keep the production default (web only); no default is weakened
// just to preserve an old test fixture.
func clientAccessFixture(t *testing.T, database *sql.DB, actor string, cipher secretstore.Cipher, host string) *service.SystemSettingsService {
	t.Helper()
	if cipher == nil {
		var err error
		cipher, err = secretstore.NewAESGCM("client-access-test", []byte(strings.Repeat("c", 32)))
		if err != nil {
			t.Fatal(err)
		}
	}
	config := settings.Defaults()
	config.ClientAccessEnabled, config.ClientAccessHost = true, host
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	secrets, err := cipher.Encrypt(ctx, []byte(`{}`), []byte("access-gateway/system-settings/secrets/v1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (&repository.SystemSettingsRepository{}).Save(ctx, database, repository.SystemSettings{ConfigJSON: encoded, SecretsCiphertext: secrets, UpdatedBy: actor}, 0); err != nil {
		t.Fatal(err)
	}
	system, err := service.NewSystemSettingsService(database, cipher, "https://"+host)
	if err != nil {
		t.Fatal(err)
	}
	return system
}
