package gatewayagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
)

type recordingEventSink struct {
	mu       sync.Mutex
	events   []gateway.ConnectionEvent
	failType string
}

func (s *recordingEventSink) Append(_ context.Context, event gateway.ConnectionEvent) error {
	if event.EventType == s.failType {
		return errors.New("audit disk unavailable")
	}
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
	return nil
}

func (s *recordingEventSink) event(eventType string) (gateway.ConnectionEvent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.EventType == eventType {
			return event, true
		}
	}
	return gateway.ConnectionEvent{}, false
}

type recordingExposure struct {
	mu      sync.Mutex
	removed int
}

func (p *recordingExposure) Ensure(_ context.Context, request ExposureRequest) (Exposure, error) {
	externalPort := request.ListenerPort
	if request.DesiredExternalPort != 0 {
		externalPort = request.DesiredExternalPort
	}
	return Exposure{Mode: "direct", Reference: fmt.Sprintf("direct/%d", request.ListenerPort), ExternalPort: externalPort}, nil
}

func (p *recordingExposure) Remove(context.Context, string, string) error {
	p.mu.Lock()
	p.removed++
	p.mu.Unlock()
	return nil
}

func (p *recordingExposure) removeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.removed
}

func newControllerForAddress(t *testing.T, backendAddress string, listenerPort int, sink ConnectionEventSink, exposure ExposureProvider) *DirectController {
	t.Helper()
	backendHost, backendPortText, err := net.SplitHostPort(backendAddress)
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}
	backendPort, _ := strconv.Atoi(backendPortText)
	resolver, err := NewStaticTargetResolver([]TargetMapEntry{{TargetID: testGatewayTargetID, Host: backendHost, Ports: []int{backendPort}}})
	if err != nil {
		t.Fatalf("NewStaticTargetResolver: %v", err)
	}
	controller, err := NewDirectController(DirectControllerOptions{
		GatewayID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", BindHost: "127.0.0.1",
		PortStart: listenerPort, PortEnd: listenerPort, DialTimeout: time.Second,
		Resolver: resolver, Exposure: exposure, Events: sink, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("NewDirectController: %v", err)
	}
	return controller
}

func waitForGatewayEvent(t *testing.T, sink *recordingEventSink, eventType string) gateway.ConnectionEvent {
	t.Helper()
	var event gateway.ConnectionEvent
	waitUntil(t, func() bool {
		var found bool
		event, found = sink.event(eventType)
		return found
	})
	return event
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before deadline")
}
