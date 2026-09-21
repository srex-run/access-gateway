// Package mailer 提供一个最小的 SMTP 发信能力。
//
// # 它刻意只有一个方法
//
//	Send(ctx, to, Message) error
//
// 不做模板引擎、不做队列、不做重试策略、不做批量发送 ——
// 在出现第二个消费者之前,那些都是猜测。目前唯一的消费者是
// 用户邀请（见 docs/user-invitations-mfa.md）。
//
// # 配置从哪来
//
// System Settings,与 OIDC 的 client_secret、LDAP 的 bind_password
// 完全同一套机制:进数据库、加密存储,**不进环境变量**
// SMTP 密码复用平台已有的加密设置存储。
//
// 配置由 Composition Root 在每次 Settings 变更时推进来(SetConfig),
// 而不是本包自己去读 —— 那会让「发一封邮件」变成「依赖整个配置系统」。
//
// # 传输一定加密
//
// 只有 starttls 与 tls 两种模式,**没有明文**,也没有跳过证书校验
// 的开关。邀请链接等同于账号本身:发送它的通道要是能被中间人读到,
// 整个邀请流的安全性就归零了 —— 攻击者不需要破解任何东西,
// 只要读一封明文邮件。
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// 传输加密方式。
const (
	// TLSStartTLS 先明文连接再 STARTTLS 升级，通常是 587 端口。
	TLSStartTLS = "starttls"
	// TLSImplicit 直接建立 TLS 连接，通常是 465 端口。
	TLSImplicit = "tls"
)

// dialTimeout 是建连与整次会话的超时。
//
// 发信在**事务之外**进行（见 19 号文档:把 SMTP 调用放进事务意味着
// 一个慢的邮件服务器会一直占着数据库连接）,但它仍然挂在一个
// HTTP 请求上,因此不能没有上限。
const dialTimeout = 15 * time.Second

// ErrNotConfigured 表示 SMTP 未启用或配置不完整。
//
// ⚠️ 调用方**必须**把它当成一种正常状态处理,而不是错误:
// 邀请在 SMTP 未配置时仍然创建成功,只是响应里多返回一个
// 一次性链接由管理员转交。一个没配好的邮件服务不该卡死用户供给。
var ErrNotConfigured = errors.New("smtp is not configured")

// Config 是 SMTP 的连接参数。
type Config struct {
	Enabled  bool
	Host     string
	Port     int
	Username string
	// Password 是明文。它只在进程内存里存在 —— 来源是加密的
	// System Setting，由 Composition Root 解密后推进来。
	Password string
	From     string
	// TLSMode 是 starttls 或 tls。**没有第三个取值。**
	TLSMode string
}

// Ready 判断配置是否足够发出一封邮件。
//
// Host 与 From 是硬要求。Username / Password 不是 ——
// 很多内网中继不需要认证。
func (c Config) Ready() bool {
	return c.Enabled &&
		strings.TrimSpace(c.Host) != "" &&
		strings.TrimSpace(c.From) != "" &&
		c.Port > 0
}

// Message 是一封邮件的内容。
//
// 只有纯文本正文。不做 HTML —— 一封 HTML 邮件需要一个模板引擎、
// 一份 CSS inliner、以及在十几个客户端里的渲染测试,
// 而邀请邮件要说的事只有两句话和一个链接。
type Message struct {
	Subject string
	Body    string
}

// Mailer 是发信契约。
//
// 定义成接口是为了让 invitation 的测试能用一个假实现 ——
// 而不是为了将来换一个「Mailer 实现」。
type Mailer interface {
	Send(ctx context.Context, to string, msg Message) error
	// Ready 报告当前配置能否发信。调用方据此决定走不走降级路径。
	Ready() bool
}

// SMTPMailer 是基于 net/smtp 的实现。
type SMTPMailer struct {
	log zerolog.Logger

	mu  sync.RWMutex
	cfg Config
}

// New 构造一个尚未配置的 Mailer。
//
// 它**不**在构造时读配置:Settings 的第一次快照可能还没到,
// 而一个「构造时就要求配置齐全」的组件会让 SMTP 没配好的部署
// 起不来。
func New(log zerolog.Logger) *SMTPMailer {
	return &SMTPMailer{log: log.With().Str("component", "mailer").Logger()}
}

// SetConfig 应用一份新的配置。由 Composition Root 在 Settings 变更时调用。
func (m *SMTPMailer) SetConfig(cfg Config) {
	if cfg.TLSMode != TLSStartTLS && cfg.TLSMode != TLSImplicit {
		// 未知取值回落到更严格的那个。**绝不**回落到明文 ——
		// 那正是这里唯一不能出的错。
		cfg.TLSMode = TLSImplicit
	}

	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
}

// Ready 报告当前配置能否发信。
func (m *SMTPMailer) Ready() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.cfg.Ready()
}

// Send 发送一封邮件。
//
// ⚠️ 日志里**绝不**出现:收件地址明文、正文、密码、任何链接。
// 正文里含邀请令牌,而一条 "invitation sent to https://.../invite/xxx"
// 的日志等于把所有待兑换账号写进日志系统。
func (m *SMTPMailer) Send(ctx context.Context, to string, msg Message) error {
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()

	if !cfg.Ready() {
		return ErrNotConfigured
	}

	if _, err := mail.ParseAddress(to); err != nil {
		return fmt.Errorf("the recipient address is not valid: %w", err)
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))

	// ⚠️ ServerName 必须是配置里的 Host，不能从连接反查。
	// 反查得到的是 DNS 解析结果，那正是中间人能控制的东西。
	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	client, release, err := m.connect(ctx, addr, cfg, tlsConfig)
	if err != nil {
		return err
	}

	defer release()
	defer func() { _ = client.Close() }()

	if err := m.authenticate(client, cfg); err != nil {
		return err
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}

	if _, err := writer.Write(compose(cfg.From, to, msg)); err != nil {
		_ = writer.Close()

		return fmt.Errorf("write the message body: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish the message: %w", err)
	}

	return client.Quit()
}

// connect 按 TLS 模式建立连接。
//
// ⚠️ starttls 模式下,StartTLS 失败**返回错误**,绝不继续明文会话。
// 降级是 STARTTLS 剥离攻击的全部内容。
func (m *SMTPMailer) connect(ctx context.Context, addr string, cfg Config, tlsConfig *tls.Config) (*smtp.Client, func(), error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial smtp: %w", err)
	}
	deadline := time.Now().Add(dialTimeout)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	release := func() { stop(); _ = raw.Close() }
	var conn net.Conn = raw
	if cfg.TLSMode == TLSImplicit {
		secured := tls.Client(raw, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			release()
			return nil, nil, fmt.Errorf("smtp TLS handshake: %w", err)
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		release()
		return nil, nil, fmt.Errorf("start smtp: %w", err)
	}
	if cfg.TLSMode != TLSImplicit {
		if err := client.StartTLS(tlsConfig); err != nil {
			_ = client.Close()
			release()
			return nil, nil, fmt.Errorf("smtp STARTTLS required: %w", err)
		}
	}
	return client, release, nil
}

// authenticate 在需要时做 SMTP AUTH。
//
// 无用户名 = 不认证。很多内网中继按 IP 放行,强制认证会让它们用不了。
func (m *SMTPMailer) authenticate(client *smtp.Client, cfg Config) error {
	if strings.TrimSpace(cfg.Username) == "" {
		return nil
	}

	// ⚠️ 到这里连接**一定**已经是 TLS 了(connect 保证)。
	// net/smtp 的 PlainAuth 自己也会拒绝在非加密连接上发送凭证,
	// 那是第二道防线。
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)

	if err := client.Auth(auth); err != nil {
		// 不带原始错误往上抛太多细节 —— 有的服务器会在错误里
		// 回显用户名。
		m.log.Error().Msg("the smtp authentication was rejected")

		return errors.New("the smtp server rejected the credentials")
	}

	return nil
}

// compose 拼出一封 RFC 5322 邮件。
//
// # 头部字段必须过滤换行
//
// 一个含 \r\n 的 Subject 会让攻击者注入任意邮件头 ——
// 包括一个额外的 Bcc。这里的 Subject 来自代码里的常量,
// 但「现在是常量」不是一个能一直成立的前提。
func compose(from, to string, msg Message) []byte {
	var b strings.Builder

	b.WriteString("From: " + sanitizeHeader(from) + "\r\n")
	b.WriteString("To: " + sanitizeHeader(to) + "\r\n")
	// BEncoding 让中文标题在所有客户端里都能正确显示。
	b.WriteString("Subject: " + mime.BEncoding.Encode("UTF-8", sanitizeHeader(msg.Subject)) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(msg.Body, "\n", "\r\n"))

	return []byte(b.String())
}

// sanitizeHeader 在第一个换行处**截断**。
//
// # 为什么是截断而不是删除换行符
//
// 删除换行符会把
//
//	"admin@example.com\r\nBcc: attacker@evil.example.com"
//
// 变成
//
//	"admin@example.comBcc: attacker@evil.example.com"
//
// 那确实不再是一条注入的头（它整体是一个头的值），但攻击者
// 塞进去的文本还在,而 From 头里那一坨东西会让一部分 MTA
// 直接拒收 —— 于是邀请邮件静默地发不出去。
//
// 截断把它变成
//
//	"admin@example.com"
//
// 换行之后的内容**一定**是攻击载荷或者一次编程错误 ——
// 一个合法的邮件头值里不会有换行。丢掉它是正确的。
func sanitizeHeader(value string) string {
	if cut := strings.IndexAny(value, "\r\n"); cut >= 0 {
		return value[:cut]
	}

	return value
}

// 编译期确认实现了契约。
var _ Mailer = (*SMTPMailer)(nil)
