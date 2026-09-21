package label

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Requirement 是选择器中的单个匹配条件。
type Requirement struct {
	Key      string
	Operator Operator
	Values   []string
}

// Matches 报告 labels 是否满足本条件。
//
// 否定操作符（!=、notin）在键不存在时也视为匹配，
// 与 Kubernetes 的语义一致：「值不等于 X」包含「根本没有这个键」。
func (r Requirement) Matches(labels Labels) bool {
	value, exists := labels[r.Key]

	switch r.Operator {
	case OpEquals:
		return exists && len(r.Values) == 1 && value == r.Values[0]
	case OpNotEquals:
		return !exists || len(r.Values) != 1 || value != r.Values[0]
	case OpIn:
		return exists && containsValue(r.Values, value)
	case OpNotIn:
		return !exists || !containsValue(r.Values, value)
	case OpExists:
		return exists
	case OpNotExists:
		return !exists
	default:
		return false
	}
}

// String 返回条件的字面形式，可被 Parse 重新解析。
func (r Requirement) String() string {
	switch r.Operator {
	case OpExists:
		return r.Key
	case OpNotExists:
		return "!" + r.Key
	case OpEquals:
		return r.Key + "=" + firstValue(r.Values)
	case OpNotEquals:
		return r.Key + "!=" + firstValue(r.Values)
	case OpIn:
		return r.Key + " in (" + strings.Join(r.Values, ",") + ")"
	case OpNotIn:
		return r.Key + " notin (" + strings.Join(r.Values, ",") + ")"
	default:
		return ""
	}
}

// Validate 校验条件的键、值与操作符组合。
func (r Requirement) Validate() error {
	if err := ValidateKey(r.Key); err != nil {
		return fmt.Errorf("invalid key %q: %w", r.Key, err)
	}

	switch r.Operator {
	case OpExists, OpNotExists:
		if len(r.Values) != 0 {
			return fmt.Errorf("operator %q must not have values", r.Operator)
		}
	case OpEquals, OpNotEquals:
		if len(r.Values) != 1 {
			return fmt.Errorf("operator %q requires exactly one value", r.Operator)
		}
	case OpIn, OpNotIn:
		if len(r.Values) == 0 {
			return fmt.Errorf("operator %q requires at least one value", r.Operator)
		}
	default:
		return fmt.Errorf("unknown operator %d", r.Operator)
	}

	for _, v := range r.Values {
		if err := ValidateValue(v); err != nil {
			return fmt.Errorf("invalid value %q: %w", v, err)
		}
	}

	return nil
}

func containsValue(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}

	return false
}

func firstValue(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// Selector 是一组 Requirement 的 AND 组合。
//
// 不支持 OR：需要 OR 语义时应当创建多个 Binding，
// 使每条授权规则保持独立可审计。
//
// 零值 Selector 匹配所有资源，等价于 Everything()。
type Selector struct {
	requirements []Requirement
}

// Everything 返回匹配所有资源的选择器。
//
// 在授权场景中要格外小心：空的 subject_selector 意味着「授予所有人」。
func Everything() Selector {
	return Selector{}
}

// Nothing 返回不匹配任何资源的选择器。
func Nothing() Selector {
	// 「键存在」且「键不存在」同时成立是不可能的。
	return Selector{requirements: []Requirement{
		{Key: "access-gateway.io/none", Operator: OpExists},
		{Key: "access-gateway.io/none", Operator: OpNotExists},
	}}
}

// Requirements 返回条件列表的副本。
func (s Selector) Requirements() []Requirement {
	if len(s.requirements) == 0 {
		return nil
	}

	out := make([]Requirement, len(s.requirements))
	copy(out, s.requirements)

	return out
}

// Empty 报告选择器是否为空（匹配所有）。
func (s Selector) Empty() bool {
	return len(s.requirements) == 0
}

// Matches 报告 labels 是否满足全部条件。
func (s Selector) Matches(labels Labels) bool {
	for _, r := range s.requirements {
		if !r.Matches(labels) {
			return false
		}
	}

	return true
}

// String 返回选择器的字面形式，可被 Parse 重新解析。
func (s Selector) String() string {
	if len(s.requirements) == 0 {
		return ""
	}

	parts := make([]string, 0, len(s.requirements))
	for _, r := range s.requirements {
		parts = append(parts, r.String())
	}

	return strings.Join(parts, ",")
}

// Validate 校验全部条件。
func (s Selector) Validate() error {
	if len(s.requirements) > MaxRequirements {
		return fmt.Errorf("too many requirements: %d exceeds limit %d", len(s.requirements), MaxRequirements)
	}

	for _, r := range s.requirements {
		if err := r.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// NewSelector 从条件列表构造选择器并校验。
func NewSelector(reqs ...Requirement) (Selector, error) {
	s := Selector{requirements: reqs}
	if err := s.Validate(); err != nil {
		return Selector{}, err
	}

	return s, nil
}

// Parse 解析选择器表达式。
//
// 支持的语法（多个条件用 , 分隔，语义为 AND）：
//
//	key=value        key==value      相等
//	key!=value                       不等
//	key in (a,b)                     属于集合
//	key notin (a,b)                  不属于集合
//	key                              键存在
//	!key                             键不存在
//
// 解析使用手写状态机而非正则，避免正则回溯带来的 ReDoS 风险。
func Parse(s string) (Selector, error) {
	p := &parser{input: s}

	reqs, err := p.parseSelector()
	if err != nil {
		return Selector{}, err
	}

	sel := Selector{requirements: reqs}
	if err := sel.Validate(); err != nil {
		return Selector{}, err
	}

	return sel, nil
}

// MustParse 与 Parse 相同，但解析失败时 panic。仅用于常量表达式与测试。
func MustParse(s string) Selector {
	sel, err := Parse(s)
	if err != nil {
		panic(err)
	}

	return sel
}

// parser 是选择器表达式的手写解析器。
type parser struct {
	input string
	pos   int
}

var errUnexpectedEnd = errors.New("unexpected end of selector")

func (p *parser) parseSelector() ([]Requirement, error) {
	var reqs []Requirement

	p.skipSpace()

	if p.pos >= len(p.input) {
		return nil, nil
	}

	for {
		if len(reqs) >= MaxRequirements {
			return nil, fmt.Errorf("too many requirements: exceeds limit %d", MaxRequirements)
		}

		req, err := p.parseRequirement()
		if err != nil {
			return nil, err
		}

		reqs = append(reqs, req)

		p.skipSpace()

		if p.pos >= len(p.input) {
			break
		}

		if p.input[p.pos] != ',' {
			return nil, fmt.Errorf("expected ',' at position %d, got %q", p.pos, string(p.input[p.pos]))
		}

		p.pos++

		p.skipSpace()

		if p.pos >= len(p.input) {
			return nil, errUnexpectedEnd
		}
	}

	return reqs, nil
}

func (p *parser) parseRequirement() (Requirement, error) {
	p.skipSpace()

	if p.pos >= len(p.input) {
		return Requirement{}, errUnexpectedEnd
	}

	// !key —— 键不存在
	if p.input[p.pos] == '!' && p.pos+1 < len(p.input) && p.input[p.pos+1] != '=' {
		p.pos++

		key, err := p.parseIdentifier()
		if err != nil {
			return Requirement{}, err
		}

		return Requirement{Key: key, Operator: OpNotExists}, nil
	}

	key, err := p.parseIdentifier()
	if err != nil {
		return Requirement{}, err
	}

	p.skipSpace()

	// 到末尾或遇到分隔符 —— 键存在
	if p.pos >= len(p.input) || p.input[p.pos] == ',' {
		return Requirement{Key: key, Operator: OpExists}, nil
	}

	switch p.input[p.pos] {
	case '=':
		p.pos++
		// 支持 == 作为 = 的别名
		if p.pos < len(p.input) && p.input[p.pos] == '=' {
			p.pos++
		}

		return p.parseSingleValue(key, OpEquals)

	case '!':
		p.pos++

		if p.pos >= len(p.input) || p.input[p.pos] != '=' {
			return Requirement{}, fmt.Errorf("expected '=' after '!' at position %d", p.pos)
		}

		p.pos++

		return p.parseSingleValue(key, OpNotEquals)

	default:
		return p.parseSetOperator(key)
	}
}

// parseSingleValue 解析 =/!= 后面的单个值。
func (p *parser) parseSingleValue(key string, op Operator) (Requirement, error) {
	p.skipSpace()

	value := p.parseValueToken()

	return Requirement{Key: key, Operator: op, Values: []string{value}}, nil
}

// parseSetOperator 解析 in / notin 及其值集合。
func (p *parser) parseSetOperator(key string) (Requirement, error) {
	word, err := p.parseIdentifier()
	if err != nil {
		return Requirement{}, fmt.Errorf("expected operator after key %q: %w", key, err)
	}

	var op Operator

	switch word {
	case "in":
		op = OpIn
	case "notin":
		op = OpNotIn
	default:
		return Requirement{}, fmt.Errorf("unknown operator %q after key %q", word, key)
	}

	values, err := p.parseValueSet()
	if err != nil {
		return Requirement{}, err
	}

	return Requirement{Key: key, Operator: op, Values: values}, nil
}

// parseValueSet 解析 (a,b,c) 形式的值集合。
func (p *parser) parseValueSet() ([]string, error) {
	p.skipSpace()

	if p.pos >= len(p.input) || p.input[p.pos] != '(' {
		return nil, fmt.Errorf("expected '(' at position %d", p.pos)
	}

	p.pos++

	var values []string

	for {
		p.skipSpace()

		if p.pos >= len(p.input) {
			return nil, errUnexpectedEnd
		}

		if p.input[p.pos] == ')' {
			p.pos++

			break
		}

		values = append(values, p.parseValueToken())

		p.skipSpace()

		if p.pos >= len(p.input) {
			return nil, errUnexpectedEnd
		}

		switch p.input[p.pos] {
		case ',':
			p.pos++
		case ')':
			p.pos++

			return values, nil
		default:
			return nil, fmt.Errorf("expected ',' or ')' at position %d, got %q", p.pos, string(p.input[p.pos]))
		}
	}

	return values, nil
}

// parseIdentifier 读取一个标识符（键名或操作符关键字）。
func (p *parser) parseIdentifier() (string, error) {
	p.skipSpace()

	start := p.pos
	for p.pos < len(p.input) && isIdentifierChar(p.input[p.pos]) {
		p.pos++
	}

	if start == p.pos {
		return "", fmt.Errorf("expected identifier at position %d", start)
	}

	return p.input[start:p.pos], nil
}

// parseValueToken 读取一个值，允许为空（key= 表示空值）。
func (p *parser) parseValueToken() string {
	start := p.pos
	for p.pos < len(p.input) && isIdentifierChar(p.input[p.pos]) {
		p.pos++
	}

	return p.input[start:p.pos]
}

func (p *parser) skipSpace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t') {
		p.pos++
	}
}

// isIdentifierChar 报告字符是否可以出现在键或值中。
func isIdentifierChar(c byte) bool {
	return isAlphanumeric(c) || c == '-' || c == '_' || c == '.' || c == '/'
}

// SortRequirements 按键名稳定排序，便于生成确定性的字符串形式。
func SortRequirements(reqs []Requirement) {
	sort.SliceStable(reqs, func(i, j int) bool {
		return reqs[i].Key < reqs[j].Key
	})
}
