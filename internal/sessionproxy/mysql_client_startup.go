package sessionproxy

import (
	"strings"
	"sync"
)

// Only the worker-owned native client can supply this state. Every query is
// still forwarded and audited; startup probes get a distinct operation type.
type mysqlClientStartup struct {
	mu                      sync.Mutex
	ready                   bool
	versionSeen, syntaxSeen bool
	promptTail              string
}

func (s *mysqlClientStartup) observeOutput(data []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ready {
		return
	}
	// clientCommand fixes this prompt. Retain only enough bytes to recognize
	// it across output frames, never terminal contents or credentials.
	const prompt = "mysql> "
	output := s.promptTail + string(data)
	if strings.Contains(output, prompt) {
		s.ready = true
		s.promptTail = ""
		return
	}
	s.promptTail = output[max(0, len(output)-len(prompt)+1):]
}

func (s *mysqlClientStartup) operationType(query string) string {
	if s == nil {
		return "query"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ready {
		switch query {
		case "select @@version_comment limit 1":
			if !s.versionSeen {
				s.versionSeen = true
				return "client_version_probe"
			}
		case "select $$":
			if !s.syntaxSeen {
				s.syntaxSeen = true
				return "client_syntax_probe"
			}
		}
	}
	return "query"
}
