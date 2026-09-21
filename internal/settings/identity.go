package settings

import (
	"fmt"
	"net/mail"
	"strings"

	"github.com/srex-run/access-gateway/internal/mailer"
)

type SMTPConfig struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	From     string `json:"from"`
	TLSMode  string `json:"tls_mode"`
}

type MFAConfig struct {
	Mode   string `json:"mode"`
	Issuer string `json:"issuer"`
}

func (m MFAConfig) Required(bound, admin bool) bool {
	return bound || m.Mode == "all" || (m.Mode == "admin" && admin)
}

func (c Config) MailConfig(secrets Secrets) mailer.Config {
	return mailer.Config{Enabled: c.SMTP.Enabled, Host: c.SMTP.Host, Port: c.SMTP.Port, Username: c.SMTP.Username,
		Password: secrets.SMTPPassword, From: c.SMTP.From, TLSMode: c.SMTP.TLSMode}
}

func (c Config) validateIdentity(secrets Secrets) error {
	switch c.MFA.Mode {
	case "off", "optional", "admin", "all":
	default:
		return fmt.Errorf("请选择有效的 MFA 策略")
	}
	if strings.TrimSpace(c.MFA.Issuer) == "" || len(c.MFA.Issuer) > 64 || strings.ContainsAny(c.MFA.Issuer, ":\r\n") {
		return fmt.Errorf("验证器显示名称需为 1–64 字节，不能包含冒号或换行")
	}
	if c.InvitationTTLHours < 1 || c.InvitationTTLHours > 14*24 {
		return fmt.Errorf("邀请有效期需为 1–336 小时")
	}
	if c.SMTP.TLSMode != "starttls" && c.SMTP.TLSMode != "tls" {
		return fmt.Errorf("SMTP 仅支持 STARTTLS 或 TLS")
	}
	if c.SMTP.Port < 1 || c.SMTP.Port > 65535 || len(c.SMTP.Host) > 253 || strings.ContainsAny(c.SMTP.Host, " /\\\r\n\t") || len(c.SMTP.Username) > 256 || strings.ContainsAny(c.SMTP.Username, "\r\n") || len(secrets.SMTPPassword) > 8192 {
		return fmt.Errorf("SMTP 地址、端口或凭据无效")
	}
	if c.SMTP.Enabled {
		address, err := mail.ParseAddress(c.SMTP.From)
		if c.SMTP.Host == "" || c.BaseURL == "" || err != nil || address.Address != c.SMTP.From || strings.ContainsAny(c.SMTP.From, "\r\n") || len(c.SMTP.From) > 254 {
			return fmt.Errorf("启用 SMTP 前请配置 PUBLIC_URL、邮件服务器和有效发件邮箱")
		}
	}
	return nil
}
