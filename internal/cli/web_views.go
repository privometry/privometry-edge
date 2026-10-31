package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/guard"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/policy"
	"github.com/privometry/privometry-edge/internal/policy/merge"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/scanner/discover"
	"github.com/privometry/privometry-edge/internal/timeline"
	"github.com/privometry/privometry-edge/internal/webui"
)

// The web timeline's computed sections. Each is read-only: it reports what
// the CLI commands report, never changes anything.

// agentView is one coding agent's protection state, for the sidebar and the
// timeline's agent chips.
type agentView struct {
	Agent         string    `json:"agent"`
	Name          string    `json:"name"`
	State         string    `json:"state"` // installed, partial, stale, missing, unsupported
	FailClosed    bool      `json:"fail_closed"`
	TrustRequired bool      `json:"trust_required,omitempty"`
	Path          string    `json:"path"`
	LastCall      time.Time `json:"last_call,omitzero"`
	Calls         int       `json:"calls"`
}

func webViews(env platform.Env) map[string]webui.View {
	return map[string]webui.View{
		"agents": {TTL: 10 * time.Second, Get: func() (any, error) { return agentsView(env) }},
		"scan":   {TTL: time.Minute, Get: func() (any, error) { return scanView(env) }},
		"policy": {TTL: 10 * time.Second, Get: func() (any, error) { return policyView(env) }},
		"device": {TTL: 15 * time.Second, Get: func() (any, error) { return deviceView(env), nil }},
	}
}

func agentsView(env platform.Env) ([]agentView, error) {
	reg, err := loadAdapters(env)
	if err != nil {
		return nil, err
	}
	out := []agentView{}
	agents, _, err := guardTargets(reg, env, "")
	if err != nil {
		return out, nil // no agents found
	}
	hook, _ := resolveHook("")
	calls := map[string]timeline.AgentActivity{}
	if st, err := queryStatus(env); err == nil {
		for _, a := range st.Agents {
			calls[a.Agent] = a
		}
	}
	for _, a := range agents {
		st := guard.Check(a, guard.Options{Env: env, HookCommand: hook})
		v := agentView{Agent: string(a.Agent), Name: a.DisplayName, State: st.State, FailClosed: st.FailClosed,
			TrustRequired: st.TrustRequired, Path: discover.Display(st.Path, env.Home, "")}
		if c, ok := calls[string(a.Agent)]; ok {
			v.LastCall, v.Calls = c.LastCall, c.Calls
		}
		out = append(out, v)
	}
	return out, nil
}

// scanAgent is one agent as the Scan page shows it.
type scanAgent struct {
	discover.Agent
	Hook string `json:"hook"` // the guard state of Privometry's hook
}

func scanView(env platform.Env) (any, error) {
	reg, err := loadAdapters(env)
	if err != nil {
		return nil, err
	}
	packs, err := loadDetectors(env)
	if err != nil {
		return nil, err
	}
	sources, _ := policy.Sources(env, "", time.Now())
	res, err := scanner.Scan(reg, scanner.Options{Options: discover.Options{Env: env, Machine: true}, Detectors: packs, Allowlist: policy.Allowlist(sources)})
	if err != nil {
		return nil, err
	}
	hook, _ := resolveHook("")
	var agents []scanAgent
	for _, a := range res.Agents {
		sa := scanAgent{Agent: a, Hook: "unsupported"}
		if ad, ok := reg.Get(a.Product); ok {
			sa.Hook = guard.Check(ad, guard.Options{Env: env, HookCommand: hook}).State
		}
		agents = append(agents, sa)
	}
	return map[string]any{"scanned_at": res.ScannedAt, "agents": agents, "findings": res.Findings,
		"content_findings": res.ContentFindings, "summary": res.Summary}, nil
}

// ruleView is one rule in effect.
type ruleView struct {
	ID       string `json:"id"`
	Layer    string `json:"layer"`
	Source   string `json:"source"`
	Verdict  string `json:"verdict"`
	Category string `json:"category"`
	Mode     string `json:"mode"`
	Message  string `json:"message,omitempty"`
}

func policyView(env platform.Env) (any, error) {
	packs, err := availablePacks(env, nil)
	if err != nil {
		return nil, err
	}
	sources, errs := policy.Sources(env, "", time.Now())
	res, err := merge.Merge(merge.Input{Packs: packs, Policies: sources, Now: time.Now()})
	if err != nil {
		return nil, err
	}
	type packView struct {
		ID, Version, Title, Description string
		Rules                           int
	}
	var pv []packView
	for _, p := range packs {
		pv = append(pv, packView{p.Manifest.ID, p.Manifest.Version, p.Manifest.Title, p.Manifest.Description, len(p.Rules)})
	}
	var rules []ruleView
	userRules := 0
	for _, r := range res.Rules {
		rules = append(rules, ruleView{ID: r.ID, Layer: string(r.Layer), Source: r.Source, Verdict: string(r.Verdict),
			Category: string(r.Category), Mode: string(r.Mode), Message: r.Message})
		if r.Layer == "user" {
			userRules++
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	userPath, _ := env.UserPolicyPath()
	user := map[string]any{"path": discover.Display(userPath, env.Home, ""), "rules": userRules}
	if raw, err := os.ReadFile(userPath); err == nil {
		user["text"] = string(raw)
	}
	var problems []string
	for _, e := range errs {
		problems = append(problems, e.Error())
	}
	for _, d := range res.Diagnostics {
		problems = append(problems, d.Layer+": "+d.Message)
	}
	return map[string]any{"packs": pv, "user": user, "rules": rules, "unmatched": res.Unmatched,
		"fail_modes": res.FailModes, "problems": problems}, nil
}

func deviceView(env platform.Env) any {
	host, _ := os.Hostname()
	out := map[string]any{"host": host, "user": localUserName(), "os": osName(env), "arch": runtime.GOARCH,
		"version": buildinfo.Version, "retention_days": 30, "capture": "redacted"}
	if dir, err := env.DataDir(); err == nil {
		out["data_dir"] = discover.Display(dir, env.Home, "")
		if info, err := os.Stat(filepath.Join(dir, "privometry.db")); err == nil {
			out["db_bytes"] = info.Size()
		}
	}
	if db, err := env.DBPath(); err == nil {
		if s, err := timeline.OpenReadOnly(db); err == nil {
			out["device_id"], _ = s.State("device_id")
			s.Close()
		}
	}
	if st, err := queryStatus(env); err == nil {
		out["daemon"] = map[string]any{"version": st.Version, "pid": st.PID, "started_at": st.StartedAt}
	}
	out["checks"] = diagnose(env, false).checks
	return out
}

func osName(env platform.Env) string {
	return map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"}[env.OS()]
}

func localUserName() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if u := strings.TrimSpace(os.Getenv(k)); u != "" {
			return u
		}
	}
	return ""
}
