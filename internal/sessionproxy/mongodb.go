package sessionproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strings"
)

type bsonValue struct {
	kind byte
	data []byte
}

func (v bsonValue) text() string {
	if v.kind == 2 && len(v.data) >= 5 {
		return string(v.data[4 : len(v.data)-1])
	}
	return ""
}
func (v bsonValue) truth() bool {
	switch v.kind {
	case 1:
		return len(v.data) == 8 && math.Float64frombits(binary.LittleEndian.Uint64(v.data)) == 1
	case 8:
		return len(v.data) == 1 && v.data[0] == 1
	case 16:
		return len(v.data) == 4 && binary.LittleEndian.Uint32(v.data) == 1
	case 18:
		return len(v.data) == 8 && binary.LittleEndian.Uint64(v.data) == 1
	}
	return false
}
func bsonFields(doc []byte, depth int) (map[string]bsonValue, string, error) {
	if depth > 16 || len(doc) < 5 || int(binary.LittleEndian.Uint32(doc)) != len(doc) || doc[len(doc)-1] != 0 {
		return nil, "", ErrProtocol
	}
	fields := map[string]bsonValue{}
	first := ""
	for i := 4; i < len(doc)-1; {
		kind := doc[i]
		i++
		z := bytes.IndexByte(doc[i:], 0)
		if z < 0 || z > 1024 || len(fields) > 4096 {
			return nil, "", ErrProtocol
		}
		name := string(doc[i : i+z])
		i += z + 1
		if _, exists := fields[name]; exists {
			return nil, "", ErrProtocol
		}
		if first == "" {
			first = name
		}
		n := 0
		switch kind {
		case 1, 9, 17, 18:
			n = 8
		case 7:
			n = 12
		case 8:
			n = 1
		case 10, 6, 0x7f, 0xff:
			n = 0
		case 16:
			n = 4
		case 2, 13, 14:
			if i+4 > len(doc) {
				return nil, "", ErrProtocol
			}
			n = 4 + int(binary.LittleEndian.Uint32(doc[i:]))
			if n < 5 || i+n >= len(doc) || doc[i+n-1] != 0 {
				return nil, "", ErrProtocol
			}
		case 3, 4, 15:
			if i+4 > len(doc) {
				return nil, "", ErrProtocol
			}
			n = int(binary.LittleEndian.Uint32(doc[i:]))
			if n < 5 {
				return nil, "", ErrProtocol
			}
		case 5:
			if i+5 > len(doc) {
				return nil, "", ErrProtocol
			}
			n = 5 + int(binary.LittleEndian.Uint32(doc[i:]))
			if n < 5 {
				return nil, "", ErrProtocol
			}
		case 11:
			for j := 0; j < 2; j++ {
				z := bytes.IndexByte(doc[i+n:], 0)
				if z < 0 {
					return nil, "", ErrProtocol
				}
				n += z + 1
			}
		case 19:
			n = 16
		default:
			return nil, "", ErrProtocol
		}
		if i+n > len(doc)-1 {
			return nil, "", ErrProtocol
		}
		v := bsonValue{kind, doc[i : i+n]}
		if kind == 3 || kind == 4 {
			if _, _, e := bsonFields(v.data, depth+1); e != nil {
				return nil, "", e
			}
		}
		fields[name] = v
		i += n
	}
	return fields, first, nil
}

type mongoFrame struct {
	flags                 uint32
	raw                   []byte
	opcode                int32
	requestID, responseTo uint32
	fields                map[string]bsonValue
	command               string
}

func mongoRead(r io.Reader) (mongoFrame, error) {
	var h [16]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return mongoFrame{}, e
	}
	n := int(binary.LittleEndian.Uint32(h[:]))
	if n < 21 || n > maxFrame {
		return mongoFrame{}, ErrProtocol
	}
	p := mongoFrame{raw: make([]byte, n), opcode: int32(binary.LittleEndian.Uint32(h[12:])), requestID: binary.LittleEndian.Uint32(h[4:]), responseTo: binary.LittleEndian.Uint32(h[8:])}
	copy(p.raw, h[:])
	if _, e := io.ReadFull(r, p.raw[16:]); e != nil {
		return p, e
	}
	var doc []byte
	switch p.opcode {
	case 2013:
		flags := binary.LittleEndian.Uint32(p.raw[16:])
		p.flags = flags
		if flags & ^uint32(1|2|1<<16) != 0 {
			return p, ErrProtocol
		}
		end := len(p.raw)
		if flags&1 != 0 {
			end -= 4
		}
		for i := 20; i < end; {
			kind := p.raw[i]
			i++
			if i+4 > end {
				return p, ErrProtocol
			}
			size := int(binary.LittleEndian.Uint32(p.raw[i:]))
			if size < 5 || size > end-i {
				return p, ErrProtocol
			}
			if kind == 0 {
				if doc != nil {
					return p, ErrProtocol
				}
				doc = p.raw[i : i+size]
			} else if kind == 1 {
				z := bytes.IndexByte(p.raw[i+4:i+size], 0)
				if z < 0 {
					return p, ErrProtocol
				}
				for j := i + 4 + z + 1; j < i+size; {
					if j+4 > i+size {
						return p, ErrProtocol
					}
					l := int(binary.LittleEndian.Uint32(p.raw[j:]))
					if l < 5 || l > i+size-j {
						return p, ErrProtocol
					}
					if _, _, e := bsonFields(p.raw[j:j+l], 0); e != nil {
						return p, e
					}
					j += l
				}
			} else {
				return p, ErrProtocol
			}
			i += size
		}
	case 2004:
		z := bytes.IndexByte(p.raw[20:], 0)
		start := 20 + z + 1 + 8
		if z < 0 || start+5 > len(p.raw) {
			return p, ErrProtocol
		}
		doc = p.raw[start:]
	case 1:
		if len(p.raw) < 41 || binary.LittleEndian.Uint32(p.raw[32:]) != 1 {
			return p, ErrProtocol
		}
		doc = p.raw[36:]
	default:
		return p, ErrProtocol
	}
	f, command, e := bsonFields(doc, 0)
	p.fields, p.command = f, command
	return p, e
}

func mongoAccount(f map[string]bsonValue) (string, error) {
	if nested := f["speculativeAuthenticate"]; nested.kind == 3 {
		v, _, e := bsonFields(nested.data, 0)
		if e != nil {
			return "", e
		}
		return mongoAccount(v)
	}
	if _, ok := f["saslStart"]; !ok {
		return "", nil
	}
	mechanism := f["mechanism"].text()
	if mechanism != "SCRAM-SHA-256" && mechanism != "SCRAM-SHA-1" {
		return "", ErrProtocol
	}
	p := f["payload"]
	if p.kind != 5 || len(p.data) < 8 {
		return "", ErrProtocol
	}
	payload := string(p.data[5:])
	if !strings.HasPrefix(payload, "n,,") {
		return "", ErrProtocol
	}
	for _, part := range strings.Split(payload[3:], ",") {
		if strings.HasPrefix(part, "n=") {
			name := strings.ReplaceAll(strings.ReplaceAll(part[2:], "=2C", ","), "=3D", "=")
			return name, nil
		}
	}
	return "", ErrProtocol
}
func serveMongo(client, backend net.Conn, r *recorder) error {
	account, candidate := "unauthenticated", ""
	for {
		p, e := mongoRead(client)
		if e != nil {
			return e
		}
		cmd := strings.ToLower(p.command)
		if len(cmd) > 64 {
			return ErrProtocol
		}
		for _, ch := range cmd {
			if !(ch >= 'a' && ch <= 'z') && ch != '_' {
				return ErrProtocol
			}
		}
		if p.opcode == 2004 && cmd != "hello" && cmd != "ismaster" {
			return ErrProtocol
		}
		if p.flags&2 != 0 {
			return ErrProtocol
		}
		if compression, present := p.fields["compression"]; present {
			if compression.kind != 4 {
				return ErrProtocol
			}
			compressors, _, err := bsonFields(compression.data, 0)
			if err != nil {
				return err
			}
			// The Node driver used by mongosh advertises ["none"] by default.
			// It disables compression; actual compressed packets remain unsupported.
			for _, compressor := range compressors {
				if compressor.text() != "none" {
					return ErrProtocol
				}
			}
		}
		name, e := mongoAccount(p.fields)
		if e != nil {
			return e
		}
		if name != "" {
			if name != r.binding.Account {
				return ErrIdentity
			}
			candidate = name
		}
		switch cmd {
		case "hello", "ismaster", "saslstart", "saslcontinue", "buildinfo", "ping", "endsessions":
		default:
			if account == "unauthenticated" {
				return ErrIdentity
			}
		}
		db := clean(p.fields["$db"].text(), 200)
		collection := ""
		switch cmd {
		case "find", "aggregate", "insert", "update", "delete", "count", "distinct", "create", "drop", "findandmodify", "listindexes", "createindexes", "dropindexes", "collstats", "mapreduce":
			collection = clean(p.fields[p.command].text(), 200)
		}
		object := db
		if collection != "" {
			object += "." + collection
		}
		op, e := r.begin(account, cmd, cmd+" "+object, object, nil)
		if e != nil {
			return e
		}
		if e = writeAll(backend, p.raw); e != nil {
			return e
		}
		clear(p.raw)
		expected := p.requestID
		for {
			reply, e := mongoRead(backend)
			if e != nil {
				return e
			}
			if reply.responseTo != expected {
				return ErrProtocol
			}
			result := "failure"
			if reply.fields["ok"].truth() {
				result = "success"
				if cmd == "saslcontinue" && reply.fields["done"].truth() && candidate != "" {
					account = candidate
				}
			}
			more := reply.flags&2 != 0
			if more && p.flags&(1<<16) == 0 {
				return ErrProtocol
			}
			if !more {
				if e = op.end(result); e != nil {
					return e
				}
			}
			if e = writeAll(client, reply.raw); e != nil {
				return e
			}
			if !more {
				break
			}
			expected = reply.requestID
		}
	}
}
