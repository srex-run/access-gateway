package sessionproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/srex-run/access-gateway/internal/id"
	"github.com/srex-run/access-gateway/internal/operationaudit"
)

var ErrProtocol = errors.New("audit protocol variant is unsupported or malformed")
var ErrIdentity = errors.New("application account does not match the approved account")
var ErrAudit = errors.New("operation audit acknowledgement failed")

type Sink interface {
	AppendOperation(context.Context, operationaudit.SessionEvent) error
}
type Binding struct {
	ConnectionID, AssetID, Account, TargetHost, BackendSourceIP string
	TargetPort, BackendSourcePort                               int
}
type recorder struct {
	mysqlStartup *mysqlClientStartup
	ctx          context.Context
	binding      Binding
	protocol     string
	sink         Sink
	mu           sync.Mutex
}
type operation struct {
	r       *recorder
	event   operationaudit.SessionEvent
	started time.Time
	once    sync.Once
	err     error
}

func (r *recorder) begin(account, kind, text, object string, metadata map[string]any) (*operation, error) {
	now := time.Now().UTC()
	text = clean(text, 4000)
	object = clean(object, 500)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["account_verified"] = account != "unverified" && account != "unauthenticated"
	fp := sha256.Sum256([]byte(text))
	fingerprint := hex.EncodeToString(fp[:])
	e := operationaudit.SessionEvent{ConnectionID: r.binding.ConnectionID, OperationID: id.New(), Phase: "started", Event: operationaudit.Event{
		EventID: id.New(), Protocol: r.protocol, AssetID: r.binding.AssetID, TargetPort: r.binding.TargetPort, ActualAccount: account,
		OperationType: kind, NormalizedOperation: &text, StatementFingerprint: &fingerprint, ObjectName: &object, Result: "unknown",
		BackendSourceIP: r.binding.BackendSourceIP, BackendSourcePort: r.binding.BackendSourcePort, OccurredAt: now, Metadata: metadata,
	}}
	e.SourceRecordID = "proxy/" + e.OperationID + "/started"
	if err := r.persist(e); err != nil {
		return nil, err
	}
	return &operation{r: r, event: e, started: now}, nil
}

func (r *recorder) persist(e operationaudit.SessionEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 10*time.Second)
	defer cancel()
	if err := r.sink.AppendOperation(ctx, e); err != nil {
		return fmt.Errorf("%w: %w", ErrAudit, err)
	}
	return nil
}

func (o *operation) end(result string) error {
	o.once.Do(func() {
		e := o.event
		e.EventID = id.New()
		e.Phase = "completed"
		e.Result = result
		e.OccurredAt = time.Now().UTC()
		duration := time.Since(o.started).Milliseconds()
		e.DurationMS = &duration
		e.SourceRecordID = "proxy/" + e.OperationID + "/completed"
		o.err = o.r.persist(e)
	})
	return o.err
}

func clean(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "…"
	}
	return strings.TrimSpace(s)
}

// SQLShape never retains literal values or comments. Quoted identifiers are
// redacted too, including ambiguous MySQL double quotes and PostgreSQL dollars.
func SQLShape(sql string) string {
	// Escaping changes with MySQL NO_BACKSLASH_ESCAPES and PostgreSQL string
	// modes. Ambiguous quoting must never expose the remainder of a literal.
	if strings.Contains(sql, "\\") {
		return "[SQL with ambiguous escaping; literals redacted]"
	}
	if strings.Contains(sql, "/*!") || strings.Contains(sql, "/*M!") {
		return "[SQL executable comment; literals redacted]"
	}
	var out strings.Builder
	for i := 0; i < len(sql) && out.Len() < 3900; {
		c := sql[i]
		if c == '\'' || c == '"' || c == '`' {
			q := c
			i++
			for i < len(sql) {
				if sql[i] == '\\' {
					i += 2
					continue
				}
				if sql[i] == q {
					i++
					if i < len(sql) && sql[i] == q {
						i++
						continue
					}
					break
				}
				i++
			}
			out.WriteString(" ? ")
			continue
		}
		if c == '$' {
			j := i + 1
			for j < len(sql) && ((sql[j] >= 'a' && sql[j] <= 'z') || (sql[j] >= 'A' && sql[j] <= 'Z') || (sql[j] >= '0' && sql[j] <= '9') || sql[j] == '_') {
				j++
			}
			if j < len(sql) && sql[j] == '$' {
				tag := sql[i : j+1]
				end := strings.Index(sql[j+1:], tag)
				if end < 0 {
					break
				}
				i = j + 1 + end + len(tag)
				out.WriteString(" ? ")
				continue
			}
		}
		if c == '#' || (c == '-' && i+1 < len(sql) && sql[i+1] == '-') {
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			out.WriteByte(' ')
			continue
		}
		if c == '/' && i+1 < len(sql) && sql[i+1] == '*' {
			i += 2
			depth := 1
			for i < len(sql) && depth > 0 {
				if i+1 < len(sql) && sql[i:i+2] == "/*" {
					depth++
					i += 2
				} else if i+1 < len(sql) && sql[i:i+2] == "*/" {
					depth--
					i += 2
				} else {
					i++
				}
			}
			out.WriteByte(' ')
			continue
		}
		if c >= '0' && c <= '9' {
			for i < len(sql) && ((sql[i] >= '0' && sql[i] <= '9') || (sql[i] >= 'a' && sql[i] <= 'f') || (sql[i] >= 'A' && sql[i] <= 'F') || strings.ContainsRune(".xXeE+-", rune(sql[i]))) {
				i++
			}
			out.WriteByte('?')
			continue
		}
		out.WriteByte(c)
		i++
	}
	s := strings.Join(strings.Fields(out.String()), " ")
	upper := strings.ToUpper(s)
	// Credential-changing statements can contain unquoted secrets in some
	// dialects. Keep only the statement class for these forms.
	for _, term := range []string{"PASSWORD", "IDENTIFIED", "SECRET", "TOKEN", "CREDENTIAL"} {
		if strings.Contains(upper, term) {
			f := strings.Fields(upper)
			if len(f) > 0 {
				return f[0] + " [redacted]"
			}
			return "[redacted]"
		}
	}
	return clean(s, 4000)
}
