package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPClientDoesNotFollowGatewayRedirects(t *testing.T) {
	client, err := NewHTTPClientWithConfig(HTTPClientConfig{
		BaseURL: "https://gateway.test", Timeout: time.Second, InternalSecret: "internal-secret", RequireHTTPS: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPClientWithConfig: %v", err)
	}
	calls := 0
	client.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Fatalf("gateway redirect was followed to %s", request.URL)
		}
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Status:     "307 Temporary Redirect",
			Header:     http.Header{"Location": []string{"https://untrusted.example/collect"}},
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})
	_, err = client.CreateSession(context.Background(), "", validClientCreateRequest("session", "target", 5432))
	if err == nil || calls != 1 {
		t.Fatalf("CreateSession error=%v calls=%d", err, calls)
	}
}

func TestHTTPClientConfigCompletesMutualTLSHandshake(t *testing.T) {
	certificate, certFile, keyFile, caFile := writeMutualTLSFixture(t)
	clientCAs := x509.NewCertPool()
	certificatePEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	if !clientCAs.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append test client CA")
	}
	serverTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	client, err := NewHTTPClientWithConfig(HTTPClientConfig{
		BaseURL: "https://gateway.test", Timeout: time.Second, InternalSecret: "0123456789abcdef0123456789abcdef",
		ClientCertFile: certFile, ClientKeyFile: keyFile, RootCAFile: caFile,
		ServerName: "gateway.test", RequireHTTPS: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPClientWithConfig: %v", err)
	}
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T", client.client.Transport)
	}
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	tlsClient := tls.Client(clientSide, transport.TLSClientConfig)
	tlsServer := tls.Server(serverSide, serverTLSConfig)
	serverResult := make(chan error, 1)
	handshakeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { serverResult <- tlsServer.HandshakeContext(handshakeCtx) }()
	if err := tlsClient.HandshakeContext(handshakeCtx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}
	if state := tlsServer.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.PeerCertificates) != 1 {
		t.Fatalf("server TLS state: version=%x peer_certificates=%d", state.Version, len(state.PeerCertificates))
	}
}

func writeMutualTLSFixture(t *testing.T) (tls.Certificate, string, string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"gateway.test"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "certificate.pem")
	keyFile := filepath.Join(directory, "private-key.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	if err := os.WriteFile(certFile, certificatePEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return certificate, certFile, keyFile, certFile
}
