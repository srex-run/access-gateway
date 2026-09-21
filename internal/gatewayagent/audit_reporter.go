package gatewayagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/srex-run/access-gateway/internal/gateway"
	"github.com/srex-run/access-gateway/internal/gatewayauth"
	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/observability"
	"github.com/srex-run/access-gateway/internal/secretstore"
)

const maxAuditAcknowledgementBytes = 32 << 10

type EventSpool interface {
	ConnectionEventSink
	Pending(limit int) []gateway.ConnectionEvent
	PendingCount() int
	Ack(ctx context.Context, eventIDs []string) error
}

type AuditReporterOptions struct {
	SessionID       string
	ControlPlaneURL string
	GatewayID       string
	AuditSecret     string
	InternalSecret  string
	AllowHTTP       bool
	HTTPClient      *http.Client
	BatchSize       int
	Logger          zerolog.Logger
	Metrics         *observability.Metrics
}

type AuditReporter struct {
	sessionID string
	spool     EventSpool
	endpoint  string
	gatewayID string
	secret    string
	legacy    bool
	client    *http.Client
	batchSize int
	logger    zerolog.Logger
	metrics   *observability.Metrics
}

func NewAuditReporter(spool EventSpool, options AuditReporterOptions) (*AuditReporter, error) {
	if spool == nil {
		return nil, fmt.Errorf("gateway audit reporter requires a spool")
	}
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(options.ControlPlaneURL), "/"))
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("gateway audit control-plane URL is invalid")
	}
	if parsed.Scheme != "https" && !options.AllowHTTP {
		return nil, fmt.Errorf("gateway audit control-plane URL must use HTTPS")
	}
	options.GatewayID = strings.TrimSpace(options.GatewayID)
	if !id.IsUUID(options.GatewayID) {
		return nil, fmt.Errorf("gateway audit reporter requires a valid gateway ID")
	}
	legacy := options.AuditSecret == ""
	if options.SessionID != "" && (!id.IsUUID(options.SessionID) || legacy) {
		return nil, fmt.Errorf("session audit reporter requires a session ID and credential")
	}
	secret := options.AuditSecret
	if legacy {
		secret = options.InternalSecret
	}
	if err := secretstore.ValidateCredential([]byte(secret)); err != nil {
		return nil, fmt.Errorf("gateway audit reporter requires a valid credential: %w", err)
	}
	if !legacy && options.InternalSecret != "" && options.AuditSecret == options.InternalSecret {
		return nil, fmt.Errorf("gateway audit and management credentials must differ")
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	batchSize := options.BatchSize
	if batchSize < 1 || batchSize > 500 {
		batchSize = 100
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/internal/gateway/events/batch"
	reporter := &AuditReporter{
		sessionID: options.SessionID,
		spool:     spool, endpoint: parsed.String(), gatewayID: options.GatewayID, secret: secret, legacy: legacy,
		client: client, batchSize: batchSize, logger: options.Logger, metrics: options.Metrics,
	}
	reporter.metrics.SetAuditSpoolPending(spool.PendingCount())
	return reporter, nil
}

func (r *AuditReporter) Flush(ctx context.Context) (int, error) {
	events := r.spool.Pending(r.batchSize)
	if len(events) == 0 {
		r.metrics.SetAuditSpoolPending(r.spool.PendingCount())
		return 0, nil
	}
	for _, event := range events {
		if event.GatewayID != r.gatewayID || r.sessionID != "" && event.SessionID != r.sessionID {
			return r.finishFlush(fmt.Errorf("gateway audit spool contains an event for a different gateway"))
		}
	}
	encoded, err := json.Marshal(gateway.ConnectionEventBatch{Events: events})
	if err != nil {
		return r.finishFlush(fmt.Errorf("encode gateway audit batch: %w", err))
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return r.finishFlush(fmt.Errorf("build gateway audit request: %w", err))
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	if r.sessionID != "" {
		request.Header.Set(gatewayauth.SessionIDHeader, r.sessionID)
	}
	if r.legacy {
		request.Header.Set(gateway.InternalSecretHeader, r.secret)
	} else {
		request.Header.Set(gateway.AuditGatewayIDHeader, r.gatewayID)
		request.Header.Set(gateway.AuditSecretHeader, r.secret)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return r.finishFlush(fmt.Errorf("send gateway audit batch: control plane unavailable"))
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return r.finishFlush(fmt.Errorf("send gateway audit batch: control plane returned HTTP %d", response.StatusCode))
	}
	if err := validateAuditAcknowledgement(response.Body, events); err != nil {
		return r.finishFlush(err)
	}
	ids := make([]string, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.EventID)
	}
	if err := r.spool.Ack(ctx, ids); err != nil {
		return r.finishFlush(fmt.Errorf("acknowledge gateway audit batch: %w", err))
	}
	r.metrics.SetAuditSpoolPending(r.spool.PendingCount())
	r.metrics.ObserveAuditDelivery(len(events), nil)
	return len(events), nil
}

func (r *AuditReporter) finishFlush(err error) (int, error) {
	r.metrics.SetAuditSpoolPending(r.spool.PendingCount())
	r.metrics.ObserveAuditDelivery(0, err)
	return 0, err
}

func validateAuditAcknowledgement(body io.Reader, events []gateway.ConnectionEvent) error {
	encoded, err := io.ReadAll(io.LimitReader(body, maxAuditAcknowledgementBytes+1))
	if err != nil {
		return fmt.Errorf("read gateway audit acknowledgement: %w", err)
	}
	if len(encoded) > maxAuditAcknowledgementBytes {
		return fmt.Errorf("gateway audit acknowledgement exceeds %d bytes", maxAuditAcknowledgementBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var acknowledgement gateway.ConnectionEventBatchResponse
	if err := decoder.Decode(&acknowledgement); err != nil {
		return fmt.Errorf("decode gateway audit acknowledgement: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode gateway audit acknowledgement: %w", err)
	}
	if acknowledgement.Version != gateway.ConnectionEventBatchResponseVersion {
		return fmt.Errorf("gateway audit acknowledgement version is invalid")
	}
	if len(acknowledgement.AcceptedEventIDs) != len(events) {
		return fmt.Errorf("gateway audit acknowledgement count does not match the request")
	}
	for index, event := range events {
		if acknowledgement.AcceptedEventIDs[index] != event.EventID {
			return fmt.Errorf("gateway audit acknowledgement does not match the request")
		}
	}
	return nil
}

func (r *AuditReporter) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	r.flushAvailable(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.flushAvailable(ctx)
		}
	}
}

func (r *AuditReporter) flushAvailable(ctx context.Context) {
	for {
		count, err := r.Flush(ctx)
		if err != nil {
			if ctx.Err() == nil {
				r.logger.Error().Err(err).Bool("alert", true).Msg("report gateway audit events failed")
			}
			return
		}
		if count == 0 || count < r.batchSize {
			return
		}
	}
}
