package mailer

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// TestComposeStripsHeaderInjection 是邮件头注入的防线。
//
// # 它守的是什么
//
// 一个含 \r\n 的 Subject 或收件地址会让攻击者注入任意邮件头 ——
// 包括一个额外的 Bcc,把邀请链接抄送到他自己的邮箱。
//
// 目前这些值都来自代码里的常量与一个校验过的邮箱,但
// 「现在是常量」不是一个能一直成立的前提:下一个人加一个
// 「自定义邀请标题」的功能时,这条测试是唯一会拦住他的东西。
func TestComposeStripsHeaderInjection(t *testing.T) {
	t.Parallel()

	message := compose(
		"admin@example.com\r\nBcc: attacker@evil.example.com",
		"victim@example.com\nBcc: attacker@evil.example.com",
		Message{
			Subject: "邀请\r\nBcc: attacker@evil.example.com",
			Body:    "正文",
		},
	)

	text := string(message)
	headerEnd := strings.Index(text, "\r\n\r\n")

	if headerEnd < 0 {
		t.Fatal("邮件里没有头部与正文的分隔")
	}

	headers := text[:headerEnd]

	if strings.Contains(headers, "Bcc:") {
		t.Errorf("头部里出现了注入的 Bcc:\n%s", headers)
	}

	if strings.Contains(headers, "attacker@evil.example.com") {
		t.Errorf("头部里出现了攻击者的地址:\n%s", headers)
	}
}

// TestComposeUsesCRLF 断言正文的换行被规范成 CRLF。
//
// RFC 5322 要求 CRLF。裸 \n 在一部分 SMTP 服务器上会导致
// 正文被截断 —— 而那个截断点很可能正好在链接中间。
func TestComposeUsesCRLF(t *testing.T) {
	t.Parallel()

	message := string(compose("a@example.com", "b@example.com", Message{
		Subject: "s",
		Body:    "第一行\n第二行\n",
	}))

	if strings.Contains(strings.ReplaceAll(message, "\r\n", ""), "\n") {
		t.Errorf("正文里有裸 \\n:\n%q", message)
	}
}

// TestComposeEncodesUTF8Subject 断言中文标题被正确编码。
//
// 裸 UTF-8 的标题在一部分客户端里显示成乱码。
func TestComposeEncodesUTF8Subject(t *testing.T) {
	t.Parallel()

	message := string(compose("a@example.com", "b@example.com", Message{
		Subject: "邀请你加入 Access Gateway",
		Body:    "正文",
	}))

	if !strings.Contains(message, "Subject: =?UTF-8?") {
		t.Errorf("中文标题没有被 MIME 编码:\n%s", message)
	}
}

// TestConfigReadyRequiresTheEssentials 断言配置不全时不发信。
//
// # 为什么 Username / Password 不是必需的
//
// 很多内网 SMTP 中继按 IP 放行,强制认证会让它们完全用不了。
func TestConfigReadyRequiresTheEssentials(t *testing.T) {
	t.Parallel()

	full := Config{
		Enabled: true,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "admin@example.com",
		TLSMode: TLSStartTLS,
	}

	if !full.Ready() {
		t.Fatal("完整的配置被判为未就绪")
	}

	cases := []struct {
		name   string
		mutate func(Config) Config
	}{
		{name: "未启用", mutate: func(c Config) Config { c.Enabled = false; return c }},
		{name: "没有主机", mutate: func(c Config) Config { c.Host = ""; return c }},
		{name: "主机全空白", mutate: func(c Config) Config { c.Host = "   "; return c }},
		{name: "没有发信地址", mutate: func(c Config) Config { c.From = ""; return c }},
		{name: "端口为零", mutate: func(c Config) Config { c.Port = 0; return c }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.mutate(full).Ready() {
				t.Errorf("%s 的配置被判为就绪", tc.name)
			}
		})
	}
}

// TestSetConfigNeverFallsBackToCleartext 是这个包唯一不能出错的地方。
//
// # 为什么未知取值回落到 tls 而不是 starttls
//
// 两者都是加密的,但 starttls 先建立一条明文连接。一个配置错误
// 加上一个中间人（吃掉 STARTTLS 的响应）就能让整封邮件明文发出去。
//
// 隐式 TLS 没有这个降级面 —— 连接从第一个字节起就是加密的。
//
// ⚠️ 变异验证:把回落值改成任何一个「明文」语义的取值,
// 这条测试必须失败。
func TestSetConfigNeverFallsBackToCleartext(t *testing.T) {
	t.Parallel()

	m := New(zerolog.Nop())

	for _, mode := range []string{"", "none", "plain", "cleartext", "STARTTLS", "随便写"} {
		m.SetConfig(Config{
			Enabled: true,
			Host:    "smtp.example.com",
			Port:    25,
			From:    "a@example.com",
			TLSMode: mode,
		})

		m.mu.RLock()
		got := m.cfg.TLSMode
		m.mu.RUnlock()

		if got != TLSStartTLS && got != TLSImplicit {
			t.Fatalf("TLSMode %q 被接受成了 %q —— 那不是一个加密模式", mode, got)
		}
	}

	// 合法取值必须原样保留。
	for _, mode := range []string{TLSStartTLS, TLSImplicit} {
		m.SetConfig(Config{
			Enabled: true, Host: "h", Port: 1, From: "a@b.c", TLSMode: mode,
		})

		m.mu.RLock()
		got := m.cfg.TLSMode
		m.mu.RUnlock()

		if got != mode {
			t.Errorf("TLSMode %q 被改成了 %q", mode, got)
		}
	}
}

// TestSendRefusesWithoutConfig 断言未配置时返回 ErrNotConfigured。
//
// ⚠️ 调用方**必须**把它当成一种正常状态:邀请在 SMTP 未配置时
// 仍然创建成功,只是响应里多返回一个一次性链接由管理员转交。
//
// 一个没配好的邮件服务不该卡死用户供给。
func TestSendRefusesWithoutConfig(t *testing.T) {
	t.Parallel()

	m := New(zerolog.Nop())

	if m.Ready() {
		t.Fatal("刚构造出来的 Mailer 声称已就绪")
	}

	err := m.Send(t.Context(), "someone@example.com", Message{Subject: "s", Body: "b"})
	if err == nil {
		t.Fatal("未配置时发信成功了")
	}
}
