package sessionproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestMySQLExecutedQueryAudit(t *testing.T) {
	const probe = "select @@version_comment limit 1"
	for _, tc := range []struct {
		name    string
		web     bool
		input   string
		queries []string
		want    int
		probes  int
		ready   bool
	}{
		{"idle web terminal", true, "", nil, 0, 0, false},
		{"typing is not execution", true, "select 1", nil, 0, 0, true},
		{"reported hs input is not execution", true, "hs", nil, 0, 0, true},
		{"statement without enter is not execution", true, "select 1;", nil, 0, 0, true},
		{"enter without delimiter is not execution", true, "select\r", nil, 0, 0, true},
		{"enter is not execution", true, "\r", nil, 0, 0, true},
		{"native version probe", true, "", []string{probe}, 0, 1, false},
		{"native syntax probe", true, "", []string{"select $$"}, 0, 1, false},
		{"manual identical version query", true, "select @@version_comment limit 1;\r", []string{probe}, 1, 0, true},
		{"manual identical syntax query", true, "select $$;\r", []string{"select $$"}, 1, 0, true},
		{"external client", false, "", []string{probe, "select $$"}, 2, 0, false},
		{"repeated probes", true, "", []string{probe, "select $$", probe, "select $$"}, 2, 2, false},
		{"unrecognized startup query", true, "", []string{"select DATABASE(), USER() limit 1"}, 1, 0, false},
		{"bare select is not a syntax probe", true, "", []string{"select"}, 1, 0, false},
		{"probe with extra SQL is not initialization", true, "", []string{"select $$; select 1"}, 1, 0, false},
		{"terminal device response", true, "\x1b[1;1R", []string{probe}, 0, 1, false},
		{"typing before startup finishes", true, "select", []string{probe}, 0, 1, false},
		{"reported hs input with startup probes", true, "hs", []string{probe, "select $$"}, 0, 2, false},
		{"manual query", true, "select 1;\n", []string{"select 1"}, 1, 0, true},
		{"multiple submitted statements", true, "select 1; select 2;\r", []string{"select 1", "select 2"}, 2, 0, true},
	} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failure=%v", tc.name, failure), func(t *testing.T) {
				auth := make([]byte, 32)
				binary.LittleEndian.PutUint32(auth, auditMySQLFlags)
				auth[8] = 45
				auth = append(auth, []byte("reader\x00\x00mysql_native_password\x00")...)
				ok := []byte{0, 0, 0, 2, 0, 0, 0}
				reply := ok
				result := "success"
				if failure {
					reply = []byte{0xff, 0x7a, 0x04, '#', 'H', 'Y', '0', '0', '0'}
					result = "failure"
				}
				expectPacket := func(c net.Conn, seq byte, data []byte) error {
					p, err := mysqlRead(c)
					if err != nil {
						return err
					}
					if p.seq != seq || !bytes.Equal(p.data, data) {
						return fmt.Errorf("unexpected packet at sequence %d", seq)
					}
					return nil
				}
				auditStreamMode(t, "mysql", func(c net.Conn) error {
					if err := expectPacket(c, 2, auth); err != nil {
						return err
					}
					if err := (mysqlPacket{3, ok}).write(c); err != nil {
						return err
					}
					for _, query := range tc.queries {
						if err := expectPacket(c, 0, append([]byte{3}, query...)); err != nil {
							return err
						}
						if err := (mysqlPacket{1, reply}).write(c); err != nil {
							return err
						}
					}
					return expectPacket(c, 0, []byte{1})
				}, func(c net.Conn) error {
					if err := (mysqlPacket{2, auth}).write(c); err != nil {
						return err
					}
					if err := expectPacket(c, 3, ok); err != nil {
						return err
					}
					for _, query := range tc.queries {
						if err := (mysqlPacket{0, append([]byte{3}, query...)}).write(c); err != nil {
							return err
						}
						if err := expectPacket(c, 1, reply); err != nil {
							return err
						}
					}
					return (mysqlPacket{0, []byte{1}}).write(c)
				}, tc.web, auditStreamOptions{userInput: tc.input, clientReady: tc.ready, inspect: func(sink *recordingSink) {
					started, completed, probeStarted, probeCompleted := 0, 0, 0, 0
					for _, event := range sink.events {
						isProbe := event.OperationType == "client_version_probe" || event.OperationType == "client_syntax_probe"
						if event.OperationType != "query" && !isProbe {
							continue
						}
						if event.Phase == "started" {
							if isProbe {
								probeStarted++
							} else {
								started++
							}
						}
						if event.Phase == "completed" {
							if isProbe {
								probeCompleted++
							} else {
								completed++
							}
							if event.Result != result {
								t.Errorf("result = %q, want %q", event.Result, result)
							}
						}
					}
					if started != tc.want || completed != tc.want {
						t.Fatalf("query events started=%d completed=%d, want %d", started, completed, tc.want)
					}
					if probeStarted != tc.probes || probeCompleted != tc.probes {
						t.Fatalf("client initialization events started=%d completed=%d, want %d", probeStarted, probeCompleted, tc.probes)
					}
				}})
			})
		}
	}
}
