package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func TestLDAPBindsOverTLSAndEscapesSearchInput(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"directory.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rootCertificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	clientPipe, serverPipe := net.Pipe()
	username := `alice*)(uid=*)`
	result := make(chan error, 1)
	go func() {
		connection := tls.Server(serverPipe, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
		result <- serveLDAPTest(connection, username)
	}()
	config := LDAPConfig{URL: "ldaps://directory.example", BindDN: "cn=reader", BindPassword: "service-password", BaseDN: "dc=example", UserFilter: "(uid={username})", IDAttribute: "entryUUID", UsernameAttribute: "uid", NameAttribute: "displayName", EmailAttribute: "mail"}
	client, err := NewLDAP(config, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.tls.RootCAs = x509.NewCertPool()
	client.tls.RootCAs.AddCert(rootCertificate)
	connection := ldap.NewConn(tls.Client(clientPipe, client.tls), true)
	connection.Start()
	profile, err := client.authenticateConnection(context.Background(), connection, username, "user-password")
	if err != nil || profile.Provider != "ldap" || profile.Subject == "" || profile.Nickname != "Directory User" || profile.Username != "directory" {
		t.Fatalf("LDAP profile = %+v, err = %v", profile, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func serveLDAPTest(connection net.Conn, username string) error {
	for step := 0; step < 3; step++ {
		packet, err := ber.ReadPacket(connection)
		if err != nil {
			return err
		}
		messageID := packet.Children[0].Value.(int64)
		request := packet.Children[1]
		if step == 1 {
			if request.Tag != ldap.ApplicationSearchRequest || request.Children[6].Tag != ldap.FilterEqualityMatch || request.Children[6].Children[1].Data.String() != username {
				return fmt.Errorf("LDAP input changed filter structure")
			}
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid=alice,dc=example", ""))
			attributes := ber.NewSequence("")
			for name, value := range map[string]string{"entryUUID": "immutable-uuid", "uid": "directory", "displayName": "Directory User", "mail": "directory@example.test"} {
				attribute := ber.NewSequence("")
				attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
				values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
				values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, ""))
				attribute.AppendChild(values)
				attributes.AppendChild(attribute)
			}
			entry.AppendChild(attributes)
			if err := writeLDAPTest(connection, messageID, entry); err != nil {
				return err
			}
		} else {
			expectedDN, expectedPassword := "cn=reader", "service-password"
			if step == 2 {
				expectedDN, expectedPassword = "uid=alice,dc=example", "user-password"
			}
			if request.Tag != ldap.ApplicationBindRequest || request.Children[1].Data.String() != expectedDN || request.Children[2].Data.String() != expectedPassword {
				return fmt.Errorf("unexpected LDAP bind identity")
			}
		}
		tag := ber.Tag(ldap.ApplicationBindResponse)
		if step == 1 {
			tag = ldap.ApplicationSearchResultDone
		}
		response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
		response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		if err := writeLDAPTest(connection, messageID, response); err != nil {
			return err
		}
	}
	return nil
}

func writeLDAPTest(connection net.Conn, messageID int64, operation *ber.Packet) error {
	response := ber.NewSequence("")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, ""))
	response.AppendChild(operation)
	_, err := connection.Write(response.Bytes())
	return err
}

func TestLDAPRejectsEmptyPasswordsAndInvalidConfiguration(t *testing.T) {
	config := LDAPConfig{Enabled: true, URL: "ldaps://directory.example:636", BindDN: "cn=reader", BindPassword: "secret", BaseDN: "dc=example", UserFilter: "(uid={username})", IDAttribute: "entryUUID"}
	client, err := NewLDAP(config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Authenticate(context.Background(), "alice", ""); err == nil {
		t.Fatal("accepted empty bind password")
	}
	for _, filter := range []string{"(uid=*)", "(|(uid={username})(mail={username}))"} {
		config.UserFilter = filter
		if err := (Config{Timeout: time.Second, LDAP: config}).Validate(); err == nil {
			t.Fatal("accepted invalid filter placeholder count")
		}
	}
	config.UserFilter = "(uid={username}"
	if _, err := NewLDAP(config, time.Second); err == nil || !strings.Contains(err.Error(), "LDAP user filter") {
		t.Fatalf("invalid filter error = %v", err)
	}
}
