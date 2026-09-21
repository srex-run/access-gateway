package securetransport_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/srex-run/access-gateway/internal/securetransport"
	"github.com/srex-run/access-gateway/internal/securetransport/testclient"
)

func TestEnvelopeRejectsTamperingAndContextMixup(t *testing.T) {
	private, public, err := securetransport.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c := securetransport.Challenge{ID: "challenge", KeyID: "key", PublicKey: public,
		Binding: securetransport.Binding{Method: "POST", Path: "/api/v1/admin/cloud-accounts", Subject: "user:alice"}}
	request, client, err := testclient.Seal(c, []byte(`{"password":"secret","apikey":"long-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"version", "kid", "wrapped-key", "iv", "ciphertext", "challenge", "method", "path", "actor"} {
		t.Run(field, func(t *testing.T) {
			copyC := c
			encoded, _ := json.Marshal(request.Envelope)
			var envelope securetransport.Envelope
			_ = json.Unmarshal(encoded, &envelope)
			switch field {
			case "version":
				envelope.Version++
			case "kid":
				envelope.KeyID = "old-key"
			case "wrapped-key":
				envelope.EncryptedKey[0] ^= 1
			case "iv":
				envelope.Nonce = envelope.Nonce[:4]
			case "ciphertext":
				envelope.Ciphertext[0] ^= 1
			case "challenge":
				copyC.ID = "other"
			case "method":
				copyC.Method = "PATCH"
			case "path":
				copyC.Path += "/other"
			case "actor":
				copyC.Subject = "user:bob"
			}
			if _, _, err := securetransport.Open(private, copyC, envelope); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	plaintext, reply, err := securetransport.Open(private, c, request.Envelope)
	if err != nil || !strings.Contains(string(plaintext), "long-secret") {
		t.Fatalf("open: %v", err)
	}
	defer reply.Clear()
	sealed, err := reply.Seal(200, []byte(`{"private_key":"private-value"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(sealed)
	if strings.Contains(string(body), "private-value") {
		t.Fatal("response secret leaked")
	}
	if _, err := client.Open(200, body); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Open(201, body); err == nil {
		t.Fatal("status substitution accepted")
	}
}

func TestBrowserWebCryptoGoInteroperability(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js is required for WebCrypto interoperability")
	}
	private, public, err := securetransport.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c := securetransport.Challenge{ID: "webcrypto-challenge", KeyID: "webcrypto-key", PublicKey: public, Algorithm: securetransport.Algorithm,
		Binding: securetransport.Binding{Method: "PATCH", Path: "/api/v1/admin/settings", Subject: "user:alice"}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "testdata/webcrypto.mjs")
	in, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close(); _ = command.Process.Kill(); _ = command.Wait() }()
	if err := json.NewEncoder(in).Encode(c); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		t.Fatalf("browser did not seal request: %s", stderr.String())
	}
	var request securetransport.Request
	if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
		t.Fatal(err)
	}
	plaintext, reply, err := securetransport.Open(private, c, request.Envelope)
	if err != nil {
		t.Fatalf("WebCrypto request rejected by Go: %v", err)
	}
	defer reply.Clear()
	var payload map[string]string
	if json.Unmarshal(plaintext, &payload) != nil || payload["password"] != "密码/🔐" || len(payload["apikey"]) != 8192 {
		t.Fatal("long/unicode payload changed")
	}
	sealed, err := reply.Seal(200, []byte(`{"private_key":"Go/browser-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(in).Encode(sealed); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() || scanner.Text() != "verified" {
		t.Fatalf("Go response rejected by WebCrypto: %s", stderr.String())
	}
	_ = in.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("WebCrypto: %v: %s", err, stderr.String())
	}
}
