// Package approvalflow contains deterministic approval definitions and request
// snapshots. It has no dependency on Feishu, authentication providers or agents.
package approvalflow

import (
	"fmt"
	"strings"
	"time"

	"github.com/srex-run/access-gateway/internal/label"
)

const OwnerPlatformID = "00000000-0000-4000-8000-000000000020"

type Step struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // owners, user_selector, role_selector
	Mode     string `json:"mode"` // any, all
	Selector string `json:"selector"`
}

type Definition struct {
	ID             string       `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	Labels         label.Labels `json:"labels"`
	Enabled        bool         `json:"enabled"`
	BuiltIn        bool         `json:"built_in"`
	Revision       int64        `json:"revision"`
	AssetSelector  string       `json:"asset_selector"`
	TimeoutSeconds int          `json:"timeout_seconds"`
	Steps          []Step       `json:"steps"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type AssetPolicy struct {
	DefaultsOnly bool         `json:"defaults_only,omitempty"`
	AssetID      string       `json:"asset_id"`
	Labels       label.Labels `json:"labels"`
	Revision     int64        `json:"revision"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

type Candidate struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
}

type ResolvedStep struct {
	Step
	Level      int         `json:"level"`
	Required   int         `json:"required"`
	Candidates []Candidate `json:"candidates"`
}

type Snapshot struct {
	WorkflowID          string         `json:"workflow_id"`
	Name                string         `json:"name"`
	Revision            int64          `json:"revision"`
	AssetPolicyRevision int64          `json:"asset_policy_revision"`
	AssetLabels         label.Labels   `json:"asset_labels"`
	Steps               []ResolvedStep `json:"steps"`
}

func (v Definition) Validate() error {
	if strings.TrimSpace(v.Name) == "" || len(v.Name) > 128 || len(v.Description) > 512 {
		return fmt.Errorf("流程名称或描述无效")
	}
	if v.TimeoutSeconds < 60 || v.TimeoutSeconds > 604800 {
		return fmt.Errorf("审批期限应为 1 分钟至 7 天")
	}
	// A workflow without a selector can be assigned explicitly by an asset.
	if strings.TrimSpace(v.AssetSelector) != "" {
		if _, err := label.BindingSelector(v.AssetSelector); err != nil {
			return err
		}
	}
	if err := label.ValidateEditable(v.Labels); err != nil {
		return err
	}
	if len(v.Steps) < 1 || len(v.Steps) > 10 {
		return fmt.Errorf("流程应包含 1–10 个审批节点")
	}
	for _, s := range v.Steps {
		if strings.TrimSpace(s.Name) == "" || len(s.Name) > 128 || (s.Mode != "any" && s.Mode != "all") {
			return fmt.Errorf("审批节点名称或通过方式无效")
		}
		switch s.Kind {
		case "owners":
			if s.Selector != "" {
				return fmt.Errorf("负责人节点使用资源负责人匹配规则")
			}
		case "user_selector", "role_selector":
			if _, err := label.BindingSelector(s.Selector); err != nil {
				return err
			}
		default:
			return fmt.Errorf("未知审批人来源")
		}
	}
	return nil
}

// Ownership is an explicit AssetSelector -> UserSelector binding.
type Ownership struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	AssetSelector string    `json:"asset_selector"`
	UserSelector  string    `json:"user_selector"`
	Enabled       bool      `json:"enabled"`
	Revision      int64     `json:"revision"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (v Ownership) Validate() error {
	if strings.TrimSpace(v.Name) == "" || len(v.Name) > 128 {
		return fmt.Errorf("请输入负责人规则名称")
	}
	if _, err := label.BindingSelector(v.AssetSelector); err != nil {
		return err
	}
	_, err := label.BindingSelector(v.UserSelector)
	return err
}
