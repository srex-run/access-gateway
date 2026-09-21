package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAdminTestAccessLimits(t *testing.T) {
	for _, ttl := range []int{1, 600} {
		input := validRequestInput()
		input.TTLSeconds = ttl
		if err := validateTestAccessInput(input); err != nil {
			t.Fatal(err)
		}
	}
	for _, ttl := range []int{-1, 0, 601, 3600} {
		input := validRequestInput()
		input.TTLSeconds = ttl
		if err := validateTestAccessInput(input); !errors.Is(err, ErrValidation) {
			t.Fatalf("TTL %d accepted", ttl)
		}
	}
	input := validRequestInput()
	input.TTLSeconds = 600
	input.Emergency = true
	if err := validateTestAccessInput(input); !errors.Is(err, ErrValidation) {
		t.Fatal("emergency test accepted")
	}
	input.Emergency = false
	now := time.Now()
	input.RequestedStartAt = &now
	if err := validateTestAccessInput(input); !errors.Is(err, ErrValidation) {
		t.Fatal("scheduled test accepted")
	}
	input.ApplicantID = ""
	if _, err := (&AccessService{}).CreateTestAccessRequest(context.Background(), input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("test access did not check identity first: %v", err)
	}
}

func validRequestInput() CreateRequestInput {
	return CreateRequestInput{
		ApplicantID: "11111111-1111-4111-8111-111111111111",
		RegionID:    "22222222-2222-4222-8222-222222222222",
		AssetID:     "33333333-3333-4333-8333-333333333333",
		TargetPort:  3306, SourceIP: "127.0.0.1", TargetAccount: "readonly",
		Reason: "测试 MySQL TLS 连接", TTLSeconds: 3600, IdempotencyKey: "request-validation-test",
	}
}

func TestAccessRequestDurationAndNoScheduledStart(t *testing.T) {
	for _, ttl := range []int{0, 1, 1800, 3600, 18000} {
		input := validRequestInput()
		input.TTLSeconds = ttl
		if err := validateCreateInput(input); err != nil {
			t.Fatalf("valid duration %d: %v", ttl, err)
		}
	}
	for _, ttl := range []int{-1, 18001, 86400} {
		input := validRequestInput()
		input.TTLSeconds = ttl
		if err := validateCreateInput(input); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid duration %d accepted", ttl)
		}
	}
	input := validRequestInput()
	start := time.Now().Add(time.Hour)
	input.RequestedStartAt = &start
	if err := validateCreateInput(input); !errors.Is(err, ErrValidation) {
		t.Fatal("scheduled start accepted")
	}
}

func TestValidateCreateRequestSourceIP(t *testing.T) {
	for _, source := range []string{"", "127.0.0.1", "::1", "192.0.2.10", "2001:db8::1", "::ffff:192.0.2.10"} {
		input := validRequestInput()
		input.SourceIP = source
		if err := validateCreateInput(input); err != nil {
			t.Fatalf("exact unicast IP %q rejected: %v", source, err)
		}
	}
	for _, source := range []string{"localhost", "http://localhost:5173", "127.0.0.1:3306", "192.0.2.0/24", "0.0.0.0", "::", "224.0.0.1", "ff02::1"} {
		input := validRequestInput()
		input.SourceIP = source
		err := validateCreateInput(input)
		var validation *RequestValidationError
		if !errors.Is(err, ErrValidation) || !errors.As(err, &validation) || !strings.Contains(validation.Message, "来源 IP") {
			t.Fatalf("invalid IP %q did not return actionable validation: %v", source, err)
		}
	}
}

func TestValidateCreateRequestReportsFieldErrors(t *testing.T) {
	input := validRequestInput()
	input.TargetAccount = ""
	if err := validateCreateInput(input); err != nil {
		t.Fatalf("optional target account rejected: %v", err)
	}
	for _, sample := range []struct {
		field  string
		change func(*CreateRequestInput)
	}{
		{"申请人", func(input *CreateRequestInput) { input.ApplicantID = "invalid" }},
		{"区域", func(input *CreateRequestInput) { input.RegionID = "" }},
		{"资产", func(input *CreateRequestInput) { input.AssetID = "invalid" }},
		{"端口", func(input *CreateRequestInput) { input.TargetPort = 65536 }},
		{"账号", func(input *CreateRequestInput) { input.TargetAccount = "root\n" }},
		{"原因", func(input *CreateRequestInput) { input.Reason = " " }},
		{"提交标识", func(input *CreateRequestInput) { input.IdempotencyKey = "" }},
		{"工单", func(input *CreateRequestInput) { input.TicketNo = stringPtr(strings.Repeat("x", 129)) }},
	} {
		t.Run(sample.field, func(t *testing.T) {
			input := validRequestInput()
			sample.change(&input)
			err := validateCreateInput(input)
			var validation *RequestValidationError
			if !errors.Is(err, ErrValidation) || !errors.As(err, &validation) || !strings.Contains(validation.Message, sample.field) {
				t.Fatalf("invalid field did not return a public validation error: %v", err)
			}
		})
	}
}
