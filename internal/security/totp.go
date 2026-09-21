package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 4226/6238 规定 HOTP 用 HMAC-SHA1，不是选择
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// # 为什么这里手写 TOTP 而不是引一个库
//
// 事实标准是 github.com/pquerna/otp。实测只 import 它的 totp 子包，
// 会把 image、image/color 与整个 github.com/boombuler/barcode
// 编译进二进制 —— 因为 otp.Key 上挂着一个 Image() 方法。
//
// 而二维码在**前端**渲染：
// 后端返回图片意味着 Secret 会出现在一个可以被缓存、被截图工具抓取的
// 响应体里走一遍。
//
// 于是那个库带来的全部额外代码都是我们明确不用的：不为从不启用的
// 子系统付整包代价。
//
// # 这不是「自己写加密」
//
// HMAC 与 SHA-1 都来自标准库。本文件实现的是 RFC 4226 的**动态截断**
// 与 RFC 6238 的**时间步换算** —— 两个几十行的确定性编码，
// 而且 RFC 6238 附录 B 给了官方测试向量，totp_test.go 逐条验过。

const (
	// totpDigits 是验证码位数。6 位是全部 Authenticator App 的默认值，
	// 改成 8 会让相当一部分 App 显示不全。
	totpDigits = 6

	// totpPeriod 是时间步长。30 秒同样是 App 的通用默认。
	totpPeriod = 30 * time.Second

	// totpSecretBytes 是 Secret 的字节数。
	//
	// RFC 4226 要求至少 128 bit，推荐 160 bit（= HMAC-SHA1 的输出长度）。
	// 取 20 字节即 160 bit：再长不会增加 HMAC-SHA1 的强度，
	// 但会让 Base32 字符串长到影响手工输入。
	totpSecretBytes = 20
)

// totpEncoding 是 Base32，**不带 padding**。
//
// Authenticator App 普遍不接受 `=` 结尾的 Secret，
// 而 20 字节恰好编码成 32 个字符，本来也不需要 padding。
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret 生成一个新的 TOTP Secret。
//
// 返回 Base32 字符串 —— 那是它进数据库、进 otpauth URI 时的形状。
func NewTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretBytes)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate a totp secret: %w", err)
	}

	return totpEncoding.EncodeToString(buf), nil
}

// TOTPStep 把一个时刻换算成 RFC 6238 的时间步。
//
// 它被导出是因为**防重放需要存这个数**:同一个步只允许成功一次。
// 见 user_mfa.last_step。
func TOTPStep(t time.Time) int64 {
	return t.Unix() / int64(totpPeriod/time.Second)
}

// totpCode 按 RFC 4226 计算一个时间步的验证码。
func totpCode(secret []byte, step int64) string {
	var counter [8]byte

	binary.BigEndian.PutUint64(counter[:], uint64(step)) //nolint:gosec // 时间步非负

	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])

	sum := mac.Sum(nil)

	// RFC 4226 §5.3 动态截断:用最后一个字节的低 4 位作为偏移，
	// 从那里取 4 字节，再抹掉最高位（避免有符号解释）。
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for range totpDigits {
		mod *= 10
	}

	return fmt.Sprintf("%0*d", totpDigits, value%mod)
}

// VerifyTOTP 校验一个验证码，返回它命中的时间步。
//
// # 为什么返回时间步
//
// 调用方必须把它与 user_mfa.last_step 比较并写回 —— RFC 6238 §5.2
// 明确要求实现拒绝同一个时间步被使用两次。没有这一条,
// 在 30 秒窗口里截获一次码就能重放。
//
// # skew 的含义
//
// 允许 ±skew 个时间步。skew=1 意味着当前码、上一个码、下一个码
// 都接受 —— 覆盖手机与服务器之间几十秒的时钟差。
//
// 它每加 1，验证码的实际有效期就多 60 秒，因此
// iam.mfa.skew 有上限（见 22 号文档的 Settings 表）。
//
// # 为什么用常数时间比较
//
// 逐字符比较的提前返回会泄露「前几位对了」——
// 那把 10^6 的搜索空间降到 10×6。
func VerifyTOTP(secretBase32, code string, at time.Time, skew int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}

	secret, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secretBase32)))
	if err != nil {
		return 0, false
	}

	if skew < 0 {
		skew = 0
	}

	current := TOTPStep(at)

	// 从当前步开始向两侧扩，命中即返回它真正的步号。
	for delta := -skew; delta <= skew; delta++ {
		step := current + int64(delta)

		if subtle.ConstantTimeCompare([]byte(totpCode(secret, step)), []byte(code)) == 1 {
			return step, true
		}
	}

	return 0, false
}

// TOTPURI 生成 otpauth:// URI，供**前端**渲染成二维码。
//
// 形状见 https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//
//	otpauth://totp/Access%20Gateway:alice?secret=...&issuer=Access%20Gateway&algorithm=SHA1&digits=6&period=30
//
// label 里重复一次 issuer 是那份规范的要求 —— 不带前缀的 App
// 会把所有账号显示成同一个组。
func TOTPURI(issuer, account, secretBase32 string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = "Access Gateway"
	}

	q := url.Values{}
	q.Set("secret", secretBase32)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod/time.Second)))

	// url.Values.Encode 会把空格编成 `+`，而 otpauth 的 label 在
	// path 段里，那里 `+` 是字面加号。用 PathEscape 单独处理 label。
	label := url.PathEscape(issuer + ":" + account)

	return "otpauth://totp/" + label + "?" + q.Encode()
}
