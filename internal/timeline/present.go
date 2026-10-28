package timeline

import (
	"strings"
)

// Outcome sorts a row into one of the timeline's outcome kinds: allow, auto,
// ask, deny, would (a monitor rule would have asked or denied), config,
// alert, failmode, inventory or finding (a content detector fired). The CLI
// and the web timeline both use it.
func (r Row) Outcome() string {
	e := r.Event
	switch e.Type {
	case "config_change":
		return "config"
	case "integrity":
		return "alert"
	case "inventory":
		return "inventory"
	case "prompt":
		return "prompt"
	case "content_finding":
		return "finding"
	case "fail_mode":
		if e.FailMode != nil && e.FailMode.Mode == "closed" {
			return "deny"
		}
		return "failmode"
	}
	switch d := e.Decision; {
	case d == nil:
		return ""
	case d.Mode == "monitor" && d.WouldVerdict != "" && d.WouldVerdict != "allow":
		return "would"
	case d.Verdict == "deny":
		return "deny"
	case d.Verdict == "ask":
		return "ask"
	case d.Source == "auto_approve":
		return "auto"
	}
	return "allow"
}

// Label is how a row's outcome reads in the timeline, in capitals.
func (r Row) Label() string {
	switch o := r.Outcome(); o {
	case "":
		return "-"
	case "allow":
		return "ALLOWED"
	case "ask":
		return "ASKED"
	case "deny":
		if r.Event.Type == "fail_mode" {
			return "BLOCKED*"
		}
		return "BLOCKED"
	case "would":
		return "WOULD " + strings.ToUpper(string(r.Event.Decision.WouldVerdict))
	case "config":
		return "CONFIG"
	case "alert":
		return "ALERT"
	case "finding":
		return "FINDING"
	default:
		return strings.ToUpper(o)
	}
}

// Why explains a row in a few words: the rules that decided it, or what
// changed.
func (r Row) Why() string {
	e := r.Event
	switch {
	case e.ContentFinding != nil:
		title, _ := e.Ext["x_privometry_title"].(string)
		if title == "" {
			title = string(e.ContentFinding.Category)
		}
		return title + " (" + e.ContentFinding.DetectorID + ")"
	case e.Integrity != nil:
		return string(e.Integrity.Check)
	case e.Config != nil && e.Config.ChangedBy != "":
		return string(e.Config.Change) + " " + string(e.Config.Tier) + " " + string(e.Config.Holds[0]) + " by " + string(e.Config.ChangedBy)
	case e.Config != nil:
		return string(e.Config.Change) + " " + string(e.Config.Tier) + " config"
	case e.FailMode != nil:
		return "daemon " + strings.ReplaceAll(string(e.FailMode.Reason), "_", " ") + ", " + string(e.FailMode.Category) + " " + string(e.FailMode.Mode)
	case e.Decision != nil && len(e.Decision.RuleIDs) > 0:
		return strings.Join(e.Decision.RuleIDs, ", ")
	}
	if e.Prompt != nil {
		return "query captured without storing its text"
	}
	if reason, ok := e.Ext["x_privometry_reason"].(string); ok {
		return reason
	}
	return ""
}

// Message is the explanation Privometry gave the agent, when it gave one.
func (r Row) Message() string {
	m, _ := r.Event.Ext["x_privometry_message"].(string)
	return m
}

// Target is what the row acted on: the full command or path when it is
// stored, else the redacted target, on one line, with home shown as ~.
func (r Row) Target(home string) string {
	s := r.TargetClear
	if s == "" && r.Event.Action != nil {
		s = r.Event.Action.Target
	}
	if s == "" && r.Event.Config != nil {
		s = r.Event.Config.Path
	}
	if s == "" && r.Event.Integrity != nil {
		s = r.Event.Integrity.Path
	}
	if home != "" {
		s = strings.ReplaceAll(s, home, "~")
	}
	return strings.Join(strings.Fields(s), " ")
}

// kindNames are the short names of action kinds, as the timeline lists them.
var kindNames = map[string]string{"shell_exec": "Shell", "file_read": "Read", "file_write": "Write", "file_delete": "Delete",
	"network_fetch": "Fetch", "web_search": "Search", "mcp_call": "MCP", "subagent_spawn": "Subagent", "other": "Tool"}

// Kind names what sort of thing a row is: for a tool call, the kind of
// action (Shell, Read, Write, Delete, Fetch, Search, MCP, Subagent, Tool);
// otherwise the event's own kind (Config, Integrity, Memory, Finding).
func (r Row) Kind() string {
	e := r.Event
	switch {
	case e.Action != nil:
		if k, ok := kindNames[string(e.Action.Kind)]; ok {
			return k
		}
		return "Tool"
	case e.ContentFinding != nil:
		return "Finding"
	case e.Config != nil && e.Config.ChangedBy != "":
		return "Memory"
	case e.Config != nil:
		return "Config"
	case e.Integrity != nil:
		return "Integrity"
	case e.Prompt != nil:
		return "Query"
	}
	return ""
}

// AgentName is the agent product a row belongs to, if any.
func (r Row) AgentName() string {
	switch {
	case r.Event.Agent != nil:
		return string(r.Event.Agent.Product)
	case r.Event.Integrity != nil:
		return string(r.Event.Integrity.AgentProduct)
	case r.Event.ContentFinding != nil && r.Event.ContentFinding.Location != nil:
		return string(r.Event.ContentFinding.Location.AgentProduct)
	}
	return ""
}
