package sessionproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/srex-run/access-gateway/internal/label"
	"github.com/srex-run/access-gateway/internal/operationaudit"
)

func TestSQLShapeDoesNotExposeLiteralValues(t *testing.T) {
	for _, sql := range []string{
		"select 'customer-secret', 987654 from accounts where id = 12",
		"select $$customer-secret$$, $body$customer-secret$body$",
		"select 'abc\\', 'customer-secret'",
		"select 1 /* customer-secret /* nested */ */",
		"/*! SELECT 'customer-secret' */",
		"ALTER USER root IDENTIFIED BY 'customer-secret'",
	} {
		shape := SQLShape(sql)
		if strings.Contains(shape, "customer-secret") || strings.Contains(shape, "987654") {
			t.Fatalf("literal escaped redaction: %q", shape)
		}
	}
	if shape := SQLShape("show databases;"); shape != "show databases;" {
		t.Fatalf("ordinary statement lost: %q", shape)
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}
func TestRESPFragmentedPipelineAndTransactionOutcomes(t *testing.T) {
	first := []byte("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n")
	second := []byte("*1\r\n$4\r\nPING\r\n")
	reader := bufio.NewReader(oneByteReader{bytes.NewReader(append(append([]byte{}, first...), second...))})
	for _, want := range [][]byte{first, second} {
		got, err := respFrame(reader)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("frame boundary: %v", err)
		}
		if _, err := respArgs(got); err != nil {
			t.Fatal(err)
		}
	}
	out, err := redisExecResults([]byte("*3\r\n+OK\r\n-ERR rejected\r\n$-1\r\n"))
	if err != nil || strings.Join(out, ",") != "success,failure,success" {
		t.Fatalf("transaction results: %v %v", out, err)
	}
	_, err = respFrame(bufio.NewReader(strings.NewReader(strings.Repeat("*1\r\n", 40) + "+OK\r\n")))
	if !errors.Is(err, ErrProtocol) {
		t.Fatal("unbounded nesting accepted")
	}
}

func TestMySQLResultStreamsRowsAndFollowsMoreResults(t *testing.T) {
	packets := []mysqlPacket{
		{1, []byte{1}}, {2, []byte("column")}, {3, []byte{0xfe, 0, 0, 0, 0}},
		{4, []byte{3, 'r', 'o', 'w'}}, {5, []byte{0xfe, 0, 0, 8, 0}},
		{6, []byte{0, 0, 0, 0, 0, 0, 0}},
	}
	var wire bytes.Buffer
	for _, p := range packets {
		if err := p.write(&wire); err != nil {
			t.Fatal(err)
		}
	}
	want := append([]byte{}, wire.Bytes()...)
	var client bytes.Buffer
	result, err := mysqlResult(&client, &wire)
	if err != nil || result != "success" || !bytes.Equal(client.Bytes(), want) {
		t.Fatalf("result stream was corrupted: %s %v", result, err)
	}
	var localInfile bytes.Buffer
	_ = (mysqlPacket{1, []byte{0xfb, 's', 'e', 'c', 'r', 'e', 't'}}).write(&localInfile)
	client.Reset()
	_, err = mysqlResult(&client, &localInfile)
	if !errors.Is(err, ErrProtocol) || client.Len() != 0 {
		t.Fatal("LOCAL INFILE reached client")
	}
}

type recordingSink struct {
	events []operationaudit.SessionEvent
	err    error
}

func (s *recordingSink) AppendOperation(_ context.Context, e operationaudit.SessionEvent) error {
	s.events = append(s.events, e)
	return s.err
}
func TestRecorderRequiresAcknowledgementAndAppendsDistinctPhases(t *testing.T) {
	sink := &recordingSink{err: errors.New("offline")}
	r := &recorder{ctx: context.Background(), sink: sink, protocol: "mysql"}
	if op, err := r.begin("root", "query", "show databases;", "", nil); op != nil || !errors.Is(err, ErrAudit) {
		t.Fatal("unacknowledged request may be forwarded")
	}
	sink.err = nil
	sink.events = nil
	op, err := r.begin("root", "query", "show databases;", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = op.end("success"); err != nil {
		t.Fatal(err)
	}
	if err = op.end("failure"); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 2 {
		t.Fatal("completion was not idempotent")
	}
	start, end := sink.events[0], sink.events[1]
	if start.EventID == end.EventID || start.OperationID != end.OperationID || start.Phase != "started" || start.Result != "unknown" || end.Phase != "completed" || end.Result != "success" {
		t.Fatal("append-only evidence identity lost")
	}
}

func TestProfileSelectionDoesNotDowngradeRequiredAssets(t *testing.T) {
	labels := label.Labels{ProfileLabel: "required-mysql"}
	if err := label.ValidateEditable(labels); err != nil {
		t.Fatalf("resource admin cannot set the audit binding: %v", err)
	}
	var empty *Registry
	if _, err := empty.Select(labels, 3306); err == nil {
		t.Fatal("missing required profile silently downgraded")
	}
	p := Config{Name: "required-mysql", Selector: ProfileLabel + "=required-mysql", Port: 3306, Protocol: "mysql"}
	r := &Registry{profiles: []Config{p}}
	policy, err := r.Select(labels, 3306)
	if err != nil || policy.Protocol != "mysql" {
		t.Fatal("profile not selected")
	}
	r.profiles[0].TargetServerName = "changed.example"
	if _, err = r.Resolve(policy); err == nil {
		t.Fatal("changed profile reused an approved grant")
	}
	r.profiles = append(r.profiles, p)
	if _, err = r.Select(labels, 3306); err == nil {
		t.Fatal("ambiguous profile accepted")
	}
}

func TestProfileSelectionUsesAssetProtocolBeforePort(t *testing.T) {
	r := &Registry{profiles: []Config{
		{Name: "mysql", Protocol: "mysql", Port: 3306, Selector: ProfileLabel + "=mysql"},
		{Name: "postgresql", Protocol: "postgresql", Port: 3306, Selector: ProfileLabel + "=postgresql"},
	}}
	labels := label.Labels{ProfileLabel: AutoProfile}
	for _, test := range []struct {
		protocol string
		want     string
	}{
		{protocol: "mysql", want: "mysql"},
		{protocol: "postgres", want: "postgresql"},
	} {
		got, err := r.SelectForProtocol(labels, 3306, test.protocol)
		if err != nil || got.Profile != test.want || got.Protocol != test.want {
			t.Fatalf("protocol %s selected %+v: %v", test.protocol, got, err)
		}
	}
	if _, err := r.SelectForProtocol(labels, 3306, "redis"); err == nil {
		t.Fatal("unrelated protocol reused a same-port audit profile")
	}
}

func TestMappedMySQLPortAuditSelection(t *testing.T) {
	r := &Registry{profiles: []Config{{Name: "mysql-audit", Protocol: "mysql", Port: 3306, Selector: ProfileLabel + "=mysql-audit"}}}
	const port = 33306
	_, err := r.Select(nil, port)
	if err == nil || !strings.Contains(err.Error(), "端口 33306 没有匹配的审计规则") || !strings.Contains(err.Error(), "资源编辑页面") {
		t.Fatalf("mapped port mismatch lost its actionable reason: %v", err)
	}
	r.profiles[0].Port = port
	policy, err := r.Select(nil, port)
	if err != nil || policy.Profile != "mysql-audit" || policy.Protocol != "mysql" {
		t.Fatalf("MySQL on a non-default port did not select its configured rule: %+v %v", policy, err)
	}
	r.profiles = append(r.profiles, Config{Name: "mysql-other", Protocol: "mysql", Port: port, Selector: ProfileLabel + "=mysql-other"})
	if _, err := r.Select(nil, port); err == nil || !strings.Contains(err.Error(), "端口 33306 匹配了多条审计规则") {
		t.Fatalf("ambiguous rules lost their actionable reason: %v", err)
	}
}

func TestAutomaticProfilesRespectPortsAndOtherLabels(t *testing.T) {
	r := &Registry{profiles: []Config{
		{Name: "mysql-audit", Protocol: "mysql", Port: 3306, Selector: ProfileLabel + "=mysql-audit,env=dev"},
		{Name: "mysql-prod", Protocol: "mysql", Port: 3306, Selector: ProfileLabel + "=mysql-prod,env=prod"},
		{Name: "ssh-audit", Protocol: "ssh", Port: 22, Selector: ProfileLabel + "=ssh-audit,env=dev"},
	}}
	labels := label.Labels{ProfileLabel: AutoProfile, "env": "dev"}
	for port, want := range map[int]string{3306: "mysql-audit", 22: "ssh-audit"} {
		got, err := r.Select(labels, port)
		if err != nil || got.Profile != want {
			t.Fatalf("port %d: %s %v", port, got.Profile, err)
		}
	}
	if labels[ProfileLabel] != AutoProfile {
		t.Fatal("selection changed the asset's shared labels")
	}
	delete(labels, ProfileLabel)
	if got, err := r.Select(labels, 3306); err != nil || got.Profile != "mysql-audit" {
		t.Fatal("older unlabelled asset did not use automatic selection")
	}
	labels["env"] = "unmatched"
	if _, err := r.Select(labels, 3306); err == nil {
		t.Fatal("automatic selection bypassed the environment selector")
	}
	labels[ProfileLabel] = "mysql-audit"
	labels["env"] = "prod"
	if _, err := r.Select(labels, 3306); err == nil {
		t.Fatal("explicit profile fell back to another profile")
	}
	var absent *Registry
	if _, err := absent.Select(nil, 3306); err == nil {
		t.Fatal("missing automatic profile silently disabled audit")
	}
	labels[ProfileLabel] = AutoProfile
	labels["env"] = "dev"
	if _, err := r.Select(labels, 5432); err == nil {
		t.Fatal("automatic selection ignored the approved port")
	}
	r.profiles = append(r.profiles, Config{Name: "mysql-other", Protocol: "mysql", Port: 3306, Selector: ProfileLabel + "=mysql-other,env=dev"})
	if _, err := r.Select(labels, 3306); err == nil {
		t.Fatal("ambiguous automatic profiles accepted")
	}
	if labels[ProfileLabel] != AutoProfile || labels["env"] != "dev" {
		t.Fatal("failed selection changed the asset's shared labels")
	}
}
