package operationaudit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/id"
)

// Collector sends normalized SSH command / database audit segments. Source logs
// must be retained until success; replay preserves event IDs and is idempotent.
type Collector struct {
	client   *http.Client
	endpoint string
	secret   string
}

func NewCollector(endpoint, secret string, allowLoopbackHTTP bool) (*Collector, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("collector endpoint must be the control-plane origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(allowLoopbackHTTP && u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, fmt.Errorf("collector requires HTTPS; HTTP is limited to explicitly enabled loopback development")
	}
	if len(secret) < 32 || len(secret) > 8192 || strings.ContainsAny(secret, "\r\n") {
		return nil, fmt.Errorf("collector secret must contain 32–8192 bytes")
	}
	u.Path = "/internal/audit/operations/batch"
	return &Collector{endpoint: u.String(), secret: secret, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Forward consumes newline-delimited source events in small batches. It never
// executes commands, logs command contents or deletes the source file.
func (c *Collector) Forward(ctx context.Context, input io.Reader) (int, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 32*1024)
	batch := []Event{}
	count, line := 0, 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := c.submit(ctx, batch); err != nil {
			return err
		}
		count += len(batch)
		batch = nil
		return nil
	}
	for scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return count, fmt.Errorf("read audit segment: %w", err)
		}
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var event Event
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return count, fmt.Errorf("invalid audit record at line %d", line)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return count, fmt.Errorf("multiple JSON values at line %d", line)
		}
		if !id.IsUUID(event.EventID) || !id.IsUUID(event.AssetID) || event.SourceRecordID == "" || event.OccurredAt.IsZero() {
			return count, fmt.Errorf("missing stable event identity at line %d", line)
		}
		batch = append(batch, event)
		if len(batch) == 20 {
			if err := flush(); err != nil {
				return count, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("read audit segment: %w", err)
	}
	if err := flush(); err != nil {
		return count, err
	}
	return count, nil
}

func (c *Collector) submit(ctx context.Context, events []Event) error {
	data, err := json.Marshal(struct {
		Events []Event `json:"events"`
	}{events})
	if err != nil {
		return fmt.Errorf("encode audit batch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create audit upload: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Audit-Collector-Secret", c.secret)
	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit upload failed; retain segment and retry")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("audit upload returned HTTP %d; retain segment and retry", res.StatusCode)
	}
	var ack struct {
		Status   string `json:"status"`
		Received int    `json:"received"`
		Inserted int    `json:"inserted"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&ack); err != nil || ack.Status != "recorded" || ack.Received != len(events) || ack.Inserted < 0 || ack.Inserted > len(events) {
		return fmt.Errorf("invalid audit acknowledgement; retain segment and retry")
	}
	return nil
}
