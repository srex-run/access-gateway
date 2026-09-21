package settings

import "testing"

func TestClientAccessRequiresExplicitHost(t *testing.T) {
	cfg := Defaults()
	if cfg.ClientAccessEnabled || cfg.Validate(Secrets{}) != nil {
		t.Fatal("web defaults invalid")
	}
	cfg.ClientAccessEnabled = true
	for _, host := range []string{"", "https://gateway.test", "gateway.test:20000", "host/path", "host@evil", "0.0.0.0", "::", "224.0.0.1"} {
		cfg.ClientAccessHost = host
		if cfg.Validate(Secrets{}) == nil {
			t.Fatalf("invalid client host accepted: %q", host)
		}
	}
	for _, host := range []string{"gateway.test", "203.0.113.1", "2001:db8::1"} {
		cfg.ClientAccessHost = host
		if err := cfg.Validate(Secrets{}); err != nil {
			t.Fatal(err)
		}
	}
}
