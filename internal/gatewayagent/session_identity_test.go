package gatewayagent

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestSessionManagementTLSIsolatesClients(t *testing.T) {
	cfg := SessionConfig{}
	var err error
	cfg.Certificate, cfg.PrivateKey, err = NewSessionIdentity(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, authorized := range []bool{true, false} {
		name := "foreign_session"
		if authorized {
			name = "same_session"
		}
		t.Run(name, func(t *testing.T) {
			serverConfig, err := cfg.ManagementTLS(true)
			if err != nil {
				t.Fatal(err)
			}
			serverConfig.SessionTicketsDisabled = true
			clientConfig, err := cfg.ManagementTLS(false)
			if err != nil {
				t.Fatal(err)
			}
			if !authorized {
				certificate, key, err := NewSessionIdentity(time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				identity, err := tls.X509KeyPair([]byte(certificate), []byte(key))
				if err != nil {
					t.Fatal(err)
				}
				clientConfig.Certificates = []tls.Certificate{identity}
			}
			serverPipe, clientPipe := net.Pipe()
			defer serverPipe.Close()
			defer clientPipe.Close()
			_ = serverPipe.SetDeadline(time.Now().Add(time.Second))
			_ = clientPipe.SetDeadline(time.Now().Add(time.Second))
			server := tls.Server(serverPipe, serverConfig)
			client := tls.Client(clientPipe, clientConfig)
			serverDone := make(chan error, 1)
			go func() { serverDone <- server.Handshake() }()
			clientErr := client.Handshake()
			if !authorized {
				_ = clientPipe.Close()
			}
			serverErr := <-serverDone
			if authorized && (clientErr != nil || serverErr != nil) {
				t.Fatalf("valid mTLS: client=%v server=%v", clientErr, serverErr)
			}
			if !authorized && serverErr == nil {
				t.Fatal("another session certificate was accepted")
			}
		})
	}
}
