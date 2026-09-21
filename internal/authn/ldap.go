package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type PasswordProvider interface {
	Authenticate(context.Context, string, string) (Profile, error)
}

type LDAPClient struct {
	config  LDAPConfig
	tls     *tls.Config
	timeout time.Duration
}

func NewLDAP(config LDAPConfig, timeout time.Duration) (*LDAPClient, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}
	if _, err := ldap.CompileFilter(strings.Replace(config.UserFilter, "{username}", "test", 1)); err != nil {
		return nil, fmt.Errorf("invalid LDAP user filter")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname()}
	if config.RootCAPEM != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(config.RootCAPEM)) {
			return nil, fmt.Errorf("LDAP root CA contains no PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return &LDAPClient{config: config, tls: tlsConfig, timeout: timeout}, nil
}

func (c *LDAPClient) Authenticate(ctx context.Context, username, password string) (Profile, error) {
	if strings.TrimSpace(username) == "" || password == "" || len(username) > 256 || len(password) > 1024 {
		return Profile{}, fmt.Errorf("invalid LDAP credentials")
	}
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	connection, err := ldap.DialURL(c.config.URL, ldap.DialWithDialer(&net.Dialer{Timeout: c.timeout}), ldap.DialWithTLSConfig(c.tls))
	if err != nil {
		return Profile{}, fmt.Errorf("connect LDAP: %w", err)
	}
	return c.authenticateConnection(ctx, connection, username, password)
}

func (c *LDAPClient) authenticateConnection(ctx context.Context, connection *ldap.Conn, username, password string) (Profile, error) {
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	connection.SetTimeout(c.timeout)
	if strings.HasPrefix(c.config.URL, "ldap://") {
		if err := connection.StartTLS(c.tls); err != nil {
			return Profile{}, fmt.Errorf("LDAP StartTLS: %w", err)
		}
	}
	if err := connection.Bind(c.config.BindDN, c.config.BindPassword); err != nil {
		return Profile{}, fmt.Errorf("LDAP service bind: %w", err)
	}
	filter := strings.Replace(c.config.UserFilter, "{username}", ldap.EscapeFilter(username), 1)
	attributes := []string{c.config.IDAttribute, c.config.NameAttribute, c.config.EmailAttribute}
	if c.config.UsernameAttribute != "" {
		attributes = append(attributes, c.config.UsernameAttribute)
	}
	result, err := connection.Search(ldap.NewSearchRequest(c.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(c.timeout.Seconds())+1, false, filter,
		attributes, nil))
	if err != nil || len(result.Entries) != 1 {
		return Profile{}, fmt.Errorf("LDAP user lookup failed")
	}
	entry := result.Entries[0]
	subject := entry.GetRawAttributeValue(c.config.IDAttribute)
	if len(subject) == 0 {
		return Profile{}, fmt.Errorf("LDAP immutable ID attribute is missing")
	}
	if err := connection.Bind(entry.DN, password); err != nil {
		return Profile{}, fmt.Errorf("invalid LDAP credentials")
	}
	accountUsername := entry.GetAttributeValue(c.config.UsernameAttribute)
	if accountUsername == "" {
		accountUsername = username
	}
	return Profile{Provider: "ldap", Issuer: c.config.Issuer(), Subject: base64.RawURLEncoding.EncodeToString(subject), Username: accountUsername, Nickname: entry.GetAttributeValue(c.config.NameAttribute), Email: entry.GetAttributeValue(c.config.EmailAttribute)}, nil
}
