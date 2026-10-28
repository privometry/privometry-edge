// Package compiler turns privometry.policy/v1 rules into Cedar policy text.
//
// Cedar only decides on facts; every rule condition becomes an expression over
// the request context defined in specs/policy/v1/privometry.cedarschema. Callers
// validate files against the JSON Schema before decoding them here.
package compiler

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Rule is one policy-language rule.
type Rule struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description"`
	Category    string      `yaml:"category"`
	When        *Conditions `yaml:"when"`
	Unless      *Conditions `yaml:"unless"`
	Verdict     string      `yaml:"verdict"`
	Message     string      `yaml:"message"`
	Mode        string      `yaml:"mode"`
	FailMode    string      `yaml:"fail_mode"`
	Locked      bool        `yaml:"locked"`
	Overridable bool        `yaml:"overridable"`
}

// Conditions are facts a rule matches on. All set fields must hold; a list
// matches any of its items.
type Conditions struct {
	Action             List     `yaml:"action"`
	Intent             List     `yaml:"intent"`
	Category           List     `yaml:"category"`
	RiskAtLeast        string   `yaml:"risk_at_least"`
	Program            List     `yaml:"program"`
	Subcommand         List     `yaml:"subcommand"`
	Flags              []string `yaml:"flags"`
	PathClass          List     `yaml:"path_class"`
	TargetPath         List     `yaml:"target_path"`
	Host               List     `yaml:"host"`
	MCPServer          List     `yaml:"mcp_server"`
	MCPTool            List     `yaml:"mcp_tool"`
	CatalogStatus      List     `yaml:"catalog_status"`
	UntrustedInputSeen *bool    `yaml:"untrusted_input_seen"`
	SecretDetected     List     `yaml:"secret_detected"` // kinds, or any
	InjectionDetected  List     `yaml:"injection_detected"`
	InjectionSeen      *bool    `yaml:"injection_seen"`
	HiddenContent      *bool    `yaml:"hidden_content"`
	TargetClass        List     `yaml:"target_class"`
	Agent              List     `yaml:"agent"`
	Repo               List     `yaml:"repo"`
}

// List accepts a YAML scalar or sequence of strings.
type List []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (l *List) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*l = List{n.Value}
		return nil
	case yaml.SequenceNode:
		var s []string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = s
		return nil
	}
	return fmt.Errorf("line %d: want a string or a list of strings", n.Line)
}

// Policy is a privometry.policy/v1 file. Overrides and exceptions are applied by
// internal/policy/merge when layers are combined.
type Policy struct {
	Schema      string              `yaml:"schema"`
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Extends     []string            `yaml:"extends"`
	Defaults    Defaults            `yaml:"defaults"`
	Rules       []Rule              `yaml:"rules"`
	Overrides   map[string]Override `yaml:"overrides"`
	Exceptions  []Exception         `yaml:"exceptions"`
	Allowlist   []AllowEntry        `yaml:"allowlist"`
}

// AllowEntry ignores content findings of some detectors where its paths,
// values or both match (PRD SCAN-09). It does not affect rules: the
// content scanner applies it before facts reach the policy.
type AllowEntry struct {
	Detectors []string `yaml:"detectors"`
	Paths     []string `yaml:"paths"`
	Values    []string `yaml:"values"`
	Reason    string   `yaml:"reason"`
	ExpiresAt string   `yaml:"expires_at"`
}

// Override changes a rule from another layer or pack. Written either as a
// verdict ("deny") or as an object with any of the fields.
type Override struct {
	Verdict  string `yaml:"verdict"`
	Mode     string `yaml:"mode"`
	FailMode string `yaml:"fail_mode"`
	Message  string `yaml:"message"`
}

// UnmarshalYAML accepts a bare verdict or an object.
func (o *Override) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		o.Verdict = n.Value
		return nil
	}
	type plain Override
	return n.Decode((*plain)(o))
}

// Exception lifts one rule where its conditions hold, until ExpiresAt.
// Conditions are written inline, next to the exception's own fields.
type Exception struct {
	Rule       string `yaml:"rule"`
	Reason     string `yaml:"reason"`
	ExpiresAt  string `yaml:"expires_at"`
	ApprovedBy string `yaml:"approved_by"`
	Conditions Conditions
}

// UnmarshalYAML reads the exception fields and the inline conditions.
func (e *Exception) UnmarshalYAML(n *yaml.Node) error {
	var head struct {
		Rule       string `yaml:"rule"`
		Reason     string `yaml:"reason"`
		ExpiresAt  string `yaml:"expires_at"`
		ApprovedBy string `yaml:"approved_by"`
	}
	if err := n.Decode(&head); err != nil {
		return err
	}
	e.Rule, e.Reason, e.ExpiresAt, e.ApprovedBy = head.Rule, head.Reason, head.ExpiresAt, head.ApprovedBy
	return n.Decode(&e.Conditions)
}

// Empty reports whether no condition is set.
func (c *Conditions) Empty() bool {
	return c == nil || len(c.Action)+len(c.Intent)+len(c.Category)+len(c.Program)+len(c.Subcommand)+len(c.Flags)+
		len(c.PathClass)+len(c.TargetPath)+len(c.Host)+len(c.MCPServer)+len(c.MCPTool)+len(c.CatalogStatus)+
		len(c.Agent)+len(c.Repo)+len(c.SecretDetected)+len(c.InjectionDetected)+len(c.TargetClass) == 0 &&
		c.RiskAtLeast == "" && c.UntrustedInputSeen == nil && c.InjectionSeen == nil && c.HiddenContent == nil
}

// Defaults are a policy's default mode, unmatched behavior and fail modes.
type Defaults struct {
	Mode      string            `yaml:"mode"`
	Unmatched string            `yaml:"unmatched"`
	FailModes map[string]string `yaml:"fail_modes"`
}
