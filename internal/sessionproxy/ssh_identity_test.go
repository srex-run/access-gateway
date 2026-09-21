package sessionproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestTerminalSSHPrivateKeys(t *testing.T) {
	signer, plain := sshTestIdentity(t)
	raw, err := ssh.ParseRawPrivateKey([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(raw, "test", []byte("test-key-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := string(pem.EncodeToMemory(block))
	for _, sample := range []struct {
		name, privateKey, passphrase string
		want                         error
	}{
		{"plain", plain, "", nil},
		{"plain with optional passphrase", plain, "unused", nil},
		{"pasted whitespace and CRLF", " \ufeff\r\n" + strings.ReplaceAll(plain, "\n", "\r\n") + " \t", "", nil},
		{"encrypted", encrypted, "test-key-passphrase", nil},
		{"missing passphrase", encrypted, "", ErrSSHKeyPassphrase},
		{"wrong passphrase", encrypted, "wrong", ErrSSHKeyPassphrase},
		{"public key", string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "", ErrSSHPrivateKey},
		{"invalid", "sensitive-invalid-material", "secret", ErrSSHPrivateKey},
	} {
		t.Run(sample.name, func(t *testing.T) {
			key, err := terminalSSHSigner(sample.privateKey, sample.passphrase)
			if !errors.Is(err, sample.want) {
				t.Fatalf("unexpected failure: %v", err)
			}
			if err == nil {
				if string(key.PublicKey().Marshal()) != string(signer.PublicKey().Marshal()) {
					t.Fatal("key identity changed")
				}
				return
			}
			if !errors.Is(err, ErrIdentity) {
				t.Fatal("missing identity error category")
			}
			diagnostic := DiagnoseTerminalFailure(err)
			if diagnostic.Stage != "ssh_private_key" || strings.Contains(err.Error()+diagnostic.Detail, "sensitive-invalid-material") {
				t.Fatal("unsafe or unclassified key failure")
			}
		})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := terminalSSHSigner(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})), "")
	if err != nil || key.PublicKey().Type() != ssh.KeyAlgoRSA {
		t.Fatalf("RSA PEM key: %v", err)
	}
}
