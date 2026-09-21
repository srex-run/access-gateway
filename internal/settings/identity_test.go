package settings

import "testing"

func TestMFAPolicyAlwaysHonorsExistingBindings(t *testing.T) {
	for _, mode := range []string{"off", "optional", "admin", "all"} {
		p := MFAConfig{Mode: mode}
		if !p.Required(true, false) || !p.Required(true, true) {
			t.Fatalf("%s disables existing MFA", mode)
		}
		if p.Required(false, false) != (mode == "all") || p.Required(false, true) != (mode == "all" || mode == "admin") {
			t.Fatalf("incorrect scope: %s", mode)
		}
	}
}

func TestIdentitySettingsValidationAndSecretUpdates(t *testing.T) {
	valid := Defaults()
	valid.BaseURL = "https://access.example.com"
	valid.SMTP = SMTPConfig{Enabled: true, Host: "smtp.example.com", Port: 465, TLSMode: "tls", From: "gateway@example.com"}
	if err := valid.Validate(Secrets{}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){
		func(c *Config) { c.MFA.Mode = "unknown" },
		func(c *Config) { c.MFA.Issuer = "bad:issuer" },
		func(c *Config) { c.SMTP.TLSMode = "none" },
		func(c *Config) { c.SMTP.Port = 65536 },
		func(c *Config) { c.SMTP.Host = "smtp.example\r\nEHLO" },
		func(c *Config) { c.SMTP.From = "gateway@example.com\r\nBcc: other@example.com" },
		func(c *Config) { c.InvitationTTLHours = 0 },
		func(c *Config) { c.InvitationTTLHours = 337 },
	} {
		value := valid
		change(&value)
		if value.Validate(Secrets{}) == nil {
			t.Fatal("invalid identity configuration accepted")
		}
	}
	secret := "smtp-password"
	stored := (Secrets{}).Apply(SecretChanges{SMTPPassword: &secret})
	if !stored.Status().SMTPPassword || stored.Apply(SecretChanges{}).SMTPPassword != secret {
		t.Fatal("SMTP secret lost")
	}
	empty := ""
	if stored.Apply(SecretChanges{SMTPPassword: &empty}).Status().SMTPPassword {
		t.Fatal("SMTP secret was not cleared")
	}
}
