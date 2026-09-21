package httpapi

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/srex-run/access-gateway/internal/service"
)

// Decoder errors can contain user-supplied values. Return only static
// messages for known fields, never the decoder error or the submitted value.
func assetBodyValidation(err error) error {
	message := "资产配置格式无效，请检查 TCP 端口和隧道协议后重试"
	var fieldError *json.UnmarshalTypeError
	if errors.As(err, &fieldError) {
		switch fieldError.Field {
		case "audit.profiles.port":
			message = "TCP 端口必须填写 1-65535 之间的整数"
		case "max_ttl_seconds":
			message = "最长访问时限必须填写 1-18000 之间的整数秒数"
		case "audit.revision":
			message = "资产审计配置版本格式无效，请刷新页面后重新编辑"
		}
	} else if strings.HasPrefix(err.Error(), "json: unknown field ") {
		message = "提交包含服务不支持的资产字段，请刷新页面并确认前后端版本一致"
	}
	return &service.RequestValidationError{Message: message}
}
