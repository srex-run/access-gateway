package cmdb

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClientFetchesStrictPaginatedSnapshot(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer 0123456789abcdef0123456789abcdef" || request.URL.Query().Get("limit") != "500" {
			t.Errorf("request headers/query = %v %v", request.Header, request.URL.Query())
		}
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("cursor") == "" {
			_, _ = response.Write([]byte(`{"version":1,"revision":"rev-1","authoritative":true,"assets":[{"external_id":"db-1","region_code":"cn-north","gateway_ids":["00000000-0000-4000-8000-000000000001"],"name":"db","asset_type":"postgres","target":"10.0.0.1","risk_level":"normal","max_ttl_seconds":3600,"status":"enabled","ports":[{"port":5432,"protocol":"tcp"}]}],"next_cursor":"page-2"}`))
			return
		}
		_, _ = response.Write([]byte(`{"version":1,"revision":"rev-1","authoritative":true,"assets":[],"next_cursor":""}`))
	}))
	defer server.Close()
	client, err := NewHTTPClient(HTTPClientConfig{
		Endpoint: server.URL, BearerToken: "0123456789abcdef0123456789abcdef", Timeout: time.Second, AllowHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	snapshot, err := client.FetchSnapshot(context.Background())
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	if requests != 2 || snapshot.Revision != "rev-1" || !snapshot.Authoritative || len(snapshot.Assets) != 1 || snapshot.Assets[0].ExternalID != "db-1" {
		t.Fatalf("snapshot=%+v requests=%d", snapshot, requests)
	}
}

func TestHTTPClientRejectsUnsafeTransportAndMalformedSnapshots(t *testing.T) {
	if _, err := NewHTTPClient(HTTPClientConfig{Endpoint: "http://cmdb.example/api", BearerToken: "secret"}); err == nil {
		t.Fatal("plaintext CMDB endpoint was accepted")
	}
	for name, body := range map[string]string{
		"not authoritative": `{"version":1,"revision":"r","authoritative":false,"assets":[]}`,
		"unknown field":     `{"version":1,"revision":"r","authoritative":true,"assets":[],"unexpected":true}`,
		"duplicate":         `{"version":1,"revision":"r","authoritative":true,"assets":[{"external_id":"a"},{"external_id":"a"}]}`,
		"trailing":          `{"version":1,"revision":"r","authoritative":true,"assets":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(response, body)
			}))
			defer server.Close()
			client, err := NewHTTPClient(HTTPClientConfig{Endpoint: server.URL, BearerToken: "secret", AllowHTTP: true})
			if err != nil {
				t.Fatalf("NewHTTPClient: %v", err)
			}
			if _, err := client.FetchSnapshot(context.Background()); err == nil {
				t.Fatal("malformed snapshot was accepted")
			}
		})
	}
}
