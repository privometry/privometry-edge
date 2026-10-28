// Package facts defines what the extractors produce and Cedar decides on. It
// has no dependencies, so the hook client can extract facts without loading
// the policy engine.
package facts

// Facts are one target of one action, as produced by the extractors. Zero
// values are the "does not apply" values the Cedar schema expects.
type Facts struct {
	Intent             []string
	Category           []string
	Risk               string // none, low, medium, high, critical; empty means none
	Program            string
	Subcommand         string
	Flags              []string
	PathClass          string
	TargetPath         string
	Host               string
	MCPServer          string
	MCPTool            string
	CatalogStatus      string
	UntrustedInputSeen bool

	// Content-scanning facts, set from the detectors' findings.
	SecretTypes   []string // credential kinds found in the action, never values
	Injection     string   // none, low, medium, high; empty means none
	InjectionSeen bool     // the session has read injected instructions
	HiddenContent bool
	TargetClass   string // memory_file, agent_config, code, other; empty when no file is targeted
}
