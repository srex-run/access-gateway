package security

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var localUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

func NormalizeUsername(username string) (string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !localUsername.MatchString(username) {
		return "", fmt.Errorf("username must be 3-64 ASCII letters, digits, dots, underscores or hyphens")
	}
	return username, nil
}

func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 72 {
		return "", fmt.Errorf("password must contain 12-72 bytes")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(hash), err
}

var dummyPasswordHash = sync.OnceValue(func() string {
	hash, _ := HashPassword("unused-login-timing-placeholder")
	return hash
})

func CheckPassword(hash, password string) bool {
	missing := hash == ""
	if missing {
		hash = dummyPasswordHash()
	}
	matched := len(password) <= 72 && bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	// The dummy comparison only equalizes timing. Invited accounts have no
	// password until activation, so even the dummy password must be rejected.
	return !missing && matched
}
