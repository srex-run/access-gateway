package sessionproxy

import (
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	ErrSSHPrivateKey    = errors.New("SSH private key is invalid or unsupported")
	ErrSSHKeyPassphrase = errors.New("SSH private key passphrase is missing or incorrect")
	ErrSSHHostKey       = errors.New("SSH target host key does not match")
)

func terminalSSHSigner(privateKey, passphrase string) (ssh.Signer, error) {
	// Pasting PEM/OpenSSH keys may add surrounding whitespace or a UTF-8 BOM.
	data := []byte(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(privateKey), "\ufeff")))
	defer clear(data)
	key, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return key, nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, errors.Join(ErrIdentity, ErrSSHPrivateKey)
	}
	if passphrase == "" {
		return nil, errors.Join(ErrIdentity, ErrSSHKeyPassphrase)
	}
	secret := []byte(passphrase)
	defer clear(secret)
	key, err = ssh.ParsePrivateKeyWithPassphrase(data, secret)
	if err != nil {
		return nil, errors.Join(ErrIdentity, ErrSSHKeyPassphrase)
	}
	return key, nil
}
