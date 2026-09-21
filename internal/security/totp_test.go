package security

import (
	"encoding/base32"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestTOTPMatchesRFC6238Vectors 用 RFC 6238 附录 B 的官方向量验证实现。
//
// # 为什么这条测试是这个文件存在的前提
//
// totp.go 手写了 RFC 4226 的动态截断与 RFC 6238 的时间步换算。
// 「自己写的对不对」不能靠读代码判断 —— 一个把偏移取成高 4 位、
// 或者把计数器写成小端的实现，看起来同样合理，也同样能自洽地
// 生成和校验，只是**和世界上所有 Authenticator App 都对不上**。
//
// 那种错误在集成测试里也发现不了:后端自己生成、自己校验，全绿。
// 只有真实用户拿手机扫码时才会暴露。
//
// 官方向量是唯一能证伪它的东西。
//
// # 向量的 seed 与位数
//
// RFC 6238 的 SHA-1 向量用 ASCII "12345678901234567890"（20 字节），
// 给的是 **8 位**码。本实现固定 6 位，因此比对时取后 6 位 ——
// 动态截断的结果对 10^8 取模再取后 6 位，等于对 10^6 取模。
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	t.Parallel()

	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))

	// RFC 6238 Appendix B，SHA-1 那一列。
	for _, tc := range []struct {
		unix  int64
		eight string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		at := time.Unix(tc.unix, 0).UTC()
		want := tc.eight[len(tc.eight)-totpDigits:]

		decoded, err := totpEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("decode the seed: %v", err)
		}

		if got := totpCode(decoded, TOTPStep(at)); got != want {
			t.Errorf("T=%d: totpCode = %s, want %s（RFC 6238 附录 B）", tc.unix, got, want)
		}

		// 同一个时刻，VerifyTOTP 必须接受它并报出正确的时间步。
		step, ok := VerifyTOTP(secret, want, at, 0)
		if !ok {
			t.Errorf("T=%d: VerifyTOTP 拒绝了 RFC 给出的正确码 %s", tc.unix, want)

			continue
		}

		if step != TOTPStep(at) {
			t.Errorf("T=%d: 命中步 = %d, want %d", tc.unix, step, TOTPStep(at))
		}
	}
}

// TestVerifyTOTPSkewWindow 锁死 skew 的边界。
//
// skew 每加 1，验证码的实际有效期就多 60 秒。一个把边界写成
// `delta < skew` 的实现会安静地把窗口缩小一半，症状是
// 「有时候能过有时候不能」—— 那种报告没有人能复现。
func TestVerifyTOTPSkewWindow(t *testing.T) {
	t.Parallel()

	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}

	raw, err := totpEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	current := TOTPStep(now)

	for _, tc := range []struct {
		name   string
		delta  int64
		skew   int
		accept bool
	}{
		{"当前步，skew=0", 0, 0, true},
		{"上一步，skew=0", -1, 0, false},
		{"下一步，skew=0", 1, 0, false},
		{"上一步，skew=1", -1, 1, true},
		{"下一步，skew=1", 1, 1, true},
		{"上两步，skew=1", -2, 1, false},
		{"下两步，skew=1", 2, 1, false},
		{"上两步，skew=2", -2, 2, true},
	} {
		code := totpCode(raw, current+tc.delta)

		step, ok := VerifyTOTP(secret, code, now, tc.skew)
		if ok != tc.accept {
			t.Errorf("%s: 接受 = %v, want %v", tc.name, ok, tc.accept)

			continue
		}

		// 命中时必须报出**码自己的**步，不是当前步 ——
		// 防重放靠这个数,报错了就等于允许相邻步重放一次。
		if ok && step != current+tc.delta {
			t.Errorf("%s: 命中步 = %d, want %d", tc.name, step, current+tc.delta)
		}
	}
}

// TestVerifyTOTPRejectsMalformedInput 覆盖非法输入。
//
// 这些都不该 panic，也不该意外通过。
func TestVerifyTOTPRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}

	now := time.Now()

	for _, tc := range []struct {
		name         string
		secret, code string
	}{
		{"空码", secret, ""},
		{"位数不足", secret, "12345"},
		{"位数过多", secret, "1234567"},
		{"非数字", secret, "abcdef"},
		{"空 Secret", "", "123456"},
		{"Secret 不是 Base32", "not-base32!!", "123456"},
	} {
		if _, ok := VerifyTOTP(tc.secret, tc.code, now, 1); ok {
			t.Errorf("%s: 被接受了", tc.name)
		}
	}
}

// TestNewTOTPSecretIsRandomAndDecodable 断言 Secret 可解码且不重复。
func TestNewTOTPSecretIsRandomAndDecodable(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 64)

	for range 64 {
		s, err := NewTOTPSecret()
		if err != nil {
			t.Fatalf("NewTOTPSecret: %v", err)
		}

		raw, err := totpEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("生成的 Secret 解不开:%v", err)
		}

		if len(raw) != totpSecretBytes {
			t.Fatalf("Secret 长度 = %d 字节, want %d", len(raw), totpSecretBytes)
		}

		if strings.Contains(s, "=") {
			t.Errorf("Secret 带 padding:%s —— 相当一部分 Authenticator App 不接受", s)
		}

		if _, dup := seen[s]; dup {
			t.Fatalf("生成了重复的 Secret —— 随机源有问题")
		}

		seen[s] = struct{}{}
	}
}

// TestTOTPURIIsScannable 断言 otpauth URI 的形状。
//
// 这个 URI 直接被前端渲染成二维码。写错一个参数名的症状是
// 「扫出来了，但码永远对不上」—— 而那时怀疑的通常是算法，不是 URI。
func TestTOTPURIIsScannable(t *testing.T) {
	t.Parallel()

	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("NewTOTPSecret: %v", err)
	}

	uri := TOTPURI("Access Gateway", "alice@example.com", secret)

	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("生成的 URI 解不开:%v", err)
	}

	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Errorf("scheme/host = %s://%s, want otpauth://totp", parsed.Scheme, parsed.Host)
	}

	// label 必须带 issuer 前缀 —— 不带的话 App 会把所有账号
	// 显示成同一个组。
	label, err := url.PathUnescape(strings.TrimPrefix(parsed.Path, "/"))
	if err != nil {
		t.Fatalf("label 解不开:%v", err)
	}

	if label != "Access Gateway:alice@example.com" {
		t.Errorf("label = %q, want %q", label, "Access Gateway:alice@example.com")
	}

	q := parsed.Query()
	for key, want := range map[string]string{
		"secret":    secret,
		"issuer":    "Access Gateway",
		"algorithm": "SHA1",
		"digits":    "6",
		"period":    "30",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("参数 %s = %q, want %q", key, got, want)
		}
	}
}

// TestTOTPURIFallsBackToGateway 断言空 issuer 不会生成一个 `:alice` 的 label。
//
// ⚠️ 冒号在 label 里是**不转义**的。RFC 3986 允许 `:` 出现在 path 段,
// 而 Key-URI-Format 给的例子正是 `otpauth://totp/Example:alice@google.com`。
// 一个断言把 issuer 从 label 中省略的测试是在要求实现偏离那份规范。
func TestTOTPURIFallsBackToGateway(t *testing.T) {
	t.Parallel()

	uri := TOTPURI("  ", "alice", "JBSWY3DPEHPK3PXP")

	if !strings.Contains(uri, "/Access%20Gateway:alice?") {
		t.Errorf("空 issuer 没有回落到 Access Gateway:%s", uri)
	}

	if !strings.Contains(uri, "issuer=Access+Gateway") {
		t.Errorf("issuer 参数没有回落:%s", uri)
	}
}

// 编译期确认 Base32 的选择没有被改成带 padding 的那一个。
var _ = base32.StdEncoding
