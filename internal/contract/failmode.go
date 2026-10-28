package contract

// DefaultFailModes returns the confirmed P1 fail-mode defaults by rule
// category. A fresh map is returned so callers can safely apply policy
// overrides without changing the defaults used by other components.
func DefaultFailModes() map[string]FailMode {
	return map[string]FailMode{
		"catastrophic":   FailModeClosed,
		"secrets":        FailModeAsk,
		"exfiltration":   FailModeAsk,
		"unapproved_mcp": FailModeOpen,
		"other":          FailModeOpen,
	}
}
