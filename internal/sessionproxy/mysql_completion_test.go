package sessionproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
)

func mysqlCompletionColumn(name string) []byte {
	var data []byte
	for _, value := range []string{"def", "sys", "sys_config", "sys_config", name, name} {
		data = append(data, byte(len(value)))
		data = append(data, value...)
	}
	return append(data, 12, 45, 0, 255, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0)
}

func TestMySQLDatabaseSwitchKeepsNativeCompletion(t *testing.T) {
	auth := make([]byte, 32)
	binary.LittleEndian.PutUint32(auth, auditMySQLFlags)
	auth[8] = 45
	auth = append(auth, []byte("reader\x00\x00mysql_native_password\x00")...)
	ok := []byte{0, 0, 0, 2, 0, 0, 0}
	eof := []byte{0xfe, 0, 0, 2, 0}
	// COM_FIELD_LIST definitions also carry defaults, which are streamed but
	// must never become operation previews (just like ordinary query results).
	field := append(mysqlCompletionColumn("variable"), byte(len("sensitive-value")))
	field = append(field, "sensitive-value"...)
	exchanges := []struct {
		request []byte
		replies []mysqlPacket
	}{
		{append([]byte{2}, "sys"...), []mysqlPacket{{1, ok}}},
		{append([]byte{3}, "SHOW TABLES"...), []mysqlPacket{
			{1, []byte{1}}, {2, mysqlCompletionColumn("Tables_in_sys")}, {3, eof},
			{4, append([]byte{10}, "sys_config"...)}, {5, eof},
		}},
		{append([]byte{4}, "sys_config\x00"...), []mysqlPacket{
			{1, field}, {2, append(mysqlCompletionColumn("value"), 0)}, {3, eof},
		}},
		{append([]byte{4}, "sys_config\x00sensitive-value%"...), []mysqlPacket{{1, eof}}},
		// A disappeared/inaccessible table is a server error, not a broken
		// proxy connection. Subsequent commands must still work.
		{append([]byte{4}, "missing\x00"...), []mysqlPacket{
			{1, append([]byte{0xff, 0x7a, 0x04, '#', '4', '2', 'S', '0', '2'}, "Table does not exist"...)},
		}},
		{append([]byte{3}, "SELECT DATABASE()"...), []mysqlPacket{
			{1, []byte{1}}, {2, mysqlCompletionColumn("DATABASE()")}, {3, eof},
			{4, append([]byte{3}, "sys"...)}, {5, eof},
		}},
	}
	expect := func(c net.Conn, seq byte, data []byte) error {
		p, err := mysqlRead(c)
		if err != nil {
			return err
		}
		if p.seq != seq || !bytes.Equal(p.data, data) {
			return fmt.Errorf("MySQL completion packet changed (sequence %d, want %d)", p.seq, seq)
		}
		return nil
	}
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%v", web), func(t *testing.T) {
			operations := auditStreamMode(t, "mysql", func(c net.Conn) error {
				if err := expect(c, 2, auth); err != nil {
					return err
				}
				if err := (mysqlPacket{3, ok}).write(c); err != nil {
					return err
				}
				for _, exchange := range exchanges {
					if err := expect(c, 0, exchange.request); err != nil {
						return err
					}
					for _, reply := range exchange.replies {
						if err := reply.write(c); err != nil {
							return err
						}
					}
				}
				return expect(c, 0, []byte{1})
			}, func(c net.Conn) error {
				if err := (mysqlPacket{2, auth}).write(c); err != nil {
					return err
				}
				if err := expect(c, 3, ok); err != nil {
					return err
				}
				for _, exchange := range exchanges {
					if err := (mysqlPacket{0, exchange.request}).write(c); err != nil {
						return err
					}
					for _, reply := range exchange.replies {
						if err := expect(c, reply.seq, reply.data); err != nil {
							return err
						}
					}
				}
				return (mysqlPacket{0, []byte{1}}).write(c)
			}, web)
			want := []string{"init_db", "query", "field_list", "field_list", "query"}
			if !slices.Equal(operations, want) {
				t.Fatalf("MySQL completion audit = %v, want %v", operations, want)
			}
		})
	}
}

func TestMySQLFieldListResponseBoundaries(t *testing.T) {
	field := mysqlCompletionColumn("variable")
	eof := []byte{0xfe, 0, 0, 2, 0}
	for _, tc := range []struct {
		name    string
		packets []mysqlPacket
		result  string
		wantErr error
	}{
		{"empty fields", []mysqlPacket{{1, eof}}, "success", nil},
		{"server error", []mysqlPacket{{1, []byte{0xff, 0x7a, 0x04, '#', '4', '2', 'S', '0', '2'}}}, "failure", nil},
		{"missing terminator", []mysqlPacket{{1, field}}, "", io.EOF},
		{"truncated EOF", []mysqlPacket{{1, []byte{0xfe}}}, "", ErrProtocol},
		{"out of sequence", []mysqlPacket{{2, field}}, "", ErrProtocol},
		{"local infile", []mysqlPacket{{1, append([]byte{0xfb}, "private-file"...)}}, "", ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var backend, client bytes.Buffer
			for _, packet := range tc.packets {
				if err := packet.write(&backend); err != nil {
					t.Fatal(err)
				}
			}
			wire := bytes.Clone(backend.Bytes())
			result, err := mysqlFieldListResult(&client, &backend)
			if result != tc.result || !errors.Is(err, tc.wantErr) {
				t.Fatalf("field list = %q, %v; want %q, %v", result, err, tc.result, tc.wantErr)
			}
			if err == nil && !bytes.Equal(client.Bytes(), wire) {
				t.Fatal("field list reply was changed")
			}
			if errors.Is(tc.wantErr, ErrProtocol) && client.Len() != 0 {
				t.Fatal("invalid field list reply reached client")
			}
		})
	}
	for _, count := range []int{257, 4096, 4097} {
		t.Run(fmt.Sprintf("columns=%d", count), func(t *testing.T) {
			var backend, client bytes.Buffer
			for i := 0; i < count; i++ {
				if err := (mysqlPacket{byte(i + 1), field}).write(&backend); err != nil {
					t.Fatal(err)
				}
			}
			if err := (mysqlPacket{byte(count + 1), eof}).write(&backend); err != nil {
				t.Fatal(err)
			}
			result, err := mysqlFieldListResult(&client, &backend)
			if count <= 4096 {
				if err != nil || result != "success" || backend.Len() != 0 {
					t.Fatalf("field list sequence wrap/limit failed: %q, %v", result, err)
				}
			} else if !errors.Is(err, ErrProtocol) {
				t.Fatalf("unbounded field definitions accepted: %v", err)
			}
		})
	}
}
