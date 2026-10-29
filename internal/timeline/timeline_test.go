package timeline_test

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/platform/platformtest"
	"github.com/privometry/privometry-edge/internal/timeline"
)

func open(t *testing.T) (*timeline.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "privometry.db")
	s, err := timeline.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func event(session string) *events.Event {
	return &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeAction,
		OccurredAt: contract.At(time.Now()), Device: events.Device{DeviceID: "dev_x", OS: "macos"},
		Agent:     &events.Agent{Product: contract.AgentProductClaudeCode, SessionID: session},
		Action:    &events.Action{Kind: contract.ActionKindShellExec, Risk: contract.RiskLow},
		Decision:  &events.Decision{Verdict: contract.VerdictAllow, RuleIDs: []string{"a:b"}},
		Redaction: map[string]contract.PrivacyLevel{}}
}

func TestAppendSequenceAndQuery(t *testing.T) {
	s, path := open(t)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess := "ses_A"
			if i%2 == 0 {
				sess = "ses_B"
			}
			if err := s.Append(event(sess), "ls -la"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows, err := s.Events(timeline.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 50 {
		t.Fatalf("%d rows", len(rows))
	}
	for i, r := range rows {
		if want := int64(50 - i); r.Event.DeviceSeq != want {
			t.Fatalf("row %d has device_seq %d, want %d: sequence must be gap-free", i, r.Event.DeviceSeq, want)
		}
		if r.TargetClear != "ls -la" {
			t.Errorf("target_clear %q", r.TargetClear)
		}
	}
	if b, _ := s.Events(timeline.Query{Session: "ses_B"}); len(b) != 25 {
		t.Errorf("session filter: %d", len(b))
	}
	platformtest.Private(t, path)
}

func TestDeviceIDAndSessions(t *testing.T) {
	s, path := open(t)
	id1, _ := s.DeviceID()
	id2, _ := s.DeviceID()
	if id1 == "" || id1 != id2 {
		t.Fatalf("device id unstable: %q %q", id1, id2)
	}
	now := time.Now()
	a, err := s.Session("claude_code", "native-1", "github.com/acme/api", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUntrusted(a.ID, "web_fetch"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUntrusted(a.ID, "web_fetch"); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Session state survives a daemon restart.
	s2, err := timeline.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	b, err := s2.Session("claude_code", "native-1", "", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != a.ID || !b.UntrustedInputSeen || len(b.UntrustedSources) != 1 {
		t.Errorf("session after reopen: %+v", b)
	}
	other, _ := s2.Session("cursor", "native-1", "", now)
	if other.ID == a.ID || other.UntrustedInputSeen {
		t.Errorf("sessions are per agent: %+v", other)
	}
	if id3, _ := s2.DeviceID(); id3 != id1 {
		t.Errorf("device id changed after reopen")
	}
}

func TestConfigHashObservedAt(t *testing.T) {
	s, _ := open(t)
	at := time.Date(2026, 10, 24, 8, 30, 0, 123456000, time.UTC)
	h := timeline.ConfigHash{Path: "/repo/CLAUDE.md", Tier: "project", Agent: "claude_code", SHA256: "abc", Kind: "memory"}
	if err := s.SetConfigHash(h, at); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConfigHashes()
	if err != nil {
		t.Fatal(err)
	}
	want := contract.At(at).Time
	if !got[h.Path].ObservedAt.Equal(want) {
		t.Errorf("observed_at = %s, want %s", got[h.Path].ObservedAt, want)
	}
}

func TestPromptPresentation(t *testing.T) {
	r := timeline.Row{Event: events.Event{Type: events.EventTypePrompt,
		Prompt: &events.Prompt{Fingerprint: "hmac-sha256:" + strings.Repeat("a", 64), Characters: 12}},
		TargetClear: "Query submitted (12 characters)"}
	if r.Outcome() != "prompt" || r.Label() != "PROMPT" || r.Kind() != "Query" ||
		r.Target("") != "Query submitted (12 characters)" || !strings.Contains(r.Why(), "without storing") {
		t.Errorf("prompt presentation: outcome=%q label=%q kind=%q target=%q why=%q",
			r.Outcome(), r.Label(), r.Kind(), r.Target(""), r.Why())
	}
}

func TestPrune(t *testing.T) {
	s, _ := open(t)
	old := event("ses_A")
	old.OccurredAt = contract.At(time.Now().Add(-40 * 24 * time.Hour))
	if err := s.Append(old, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(event("ses_A"), ""); err != nil {
		t.Fatal(err)
	}
	n, err := s.Prune(time.Now().Add(-30*24*time.Hour), time.Now().Add(-7*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
}

func TestQueriesAndReadOnly(t *testing.T) {
	s, path := open(t)
	for i := range 5 {
		ev := event("ses_A")
		if i == 3 {
			ev.Decision.Verdict = contract.VerdictDeny
		}
		target := "ls"
		if i == 4 {
			target = "rm -rf ~/Old"
		}
		s.Append(ev, target)
	}
	if rows, _ := s.Events(timeline.Query{Verdict: "deny"}); len(rows) != 1 {
		t.Errorf("verdict filter: %d", len(rows))
	}
	if rows, _ := s.Events(timeline.Query{Search: "RM -RF"}); len(rows) != 1 || rows[0].TargetClear != "rm -rf ~/Old" {
		t.Errorf("search: %+v", rows)
	}
	rows, _ := s.Events(timeline.Query{AfterSeq: 3})
	if len(rows) != 2 || rows[0].Event.DeviceSeq != 4 || rows[1].Event.DeviceSeq != 5 {
		t.Errorf("after_seq must return newer events oldest first: %+v", rows)
	}
	ro, err := timeline.OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if rows, err := ro.Events(timeline.Query{}); err != nil || len(rows) != 5 {
		t.Errorf("read-only: %d %v", len(rows), err)
	}
	if err := ro.Append(event("ses_B"), ""); err == nil {
		t.Error("read-only store accepted a write")
	}
	if _, err := timeline.OpenReadOnly(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Error("missing database must be an error")
	}
}

func TestPagingTallyAndOutcomes(t *testing.T) {
	s, _ := open(t)
	add := func(mut func(*events.Event), target string) {
		ev := event("ses_A")
		mut(ev)
		if err := s.Append(ev, target); err != nil {
			t.Fatal(err)
		}
	}
	add(func(e *events.Event) { e.Decision.Source, e.Decision.RuleIDs = events.DecisionSourceAutoApprove, nil }, "ls") // 1 auto
	add(func(e *events.Event) { e.Decision.Verdict = contract.VerdictAsk }, "git push")                                // 2 ask
	add(func(e *events.Event) {
		e.Decision.Verdict, e.Decision.RuleIDs = contract.VerdictDeny, []string{"privometry/x:home"}
	}, "rm") // 3 deny
	add(func(e *events.Event) {
		e.Decision.Mode, e.Decision.WouldVerdict = events.DecisionModeMonitor, contract.VerdictDeny
	}, "curl x") // 4 would deny
	add(func(e *events.Event) {
		e.Type, e.Action, e.Decision = events.EventTypeConfigChange, nil, nil
		e.Config = &events.Config{Change: "modified", Tier: "user", Path: "/home/me/.claude/settings.json"}
	}, "") // 5 config
	add(func(e *events.Event) { e.OccurredAt = contract.At(time.Now().Add(-48 * time.Hour)) }, "old") // 6, two days ago

	if rows, _ := s.Events(timeline.Query{Verdict: "ask,deny"}); len(rows) != 2 {
		t.Errorf("verdict list: %d rows", len(rows))
	}
	if rows, _ := s.Events(timeline.Query{Search: "privometry/x"}); len(rows) != 1 || rows[0].Event.DeviceSeq != 3 {
		t.Errorf("search must match rule IDs: %+v", rows)
	}
	rows, _ := s.Events(timeline.Query{BeforeSeq: 4, Limit: 2})
	if len(rows) != 2 || rows[0].Event.DeviceSeq != 3 || rows[1].Event.DeviceSeq != 2 {
		t.Errorf("before_seq must page back newest first: %+v", rows)
	}
	tally, err := s.Tally(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if want := (timeline.Tally{Actions: 4, Auto: 1, Asked: 1, Blocked: 1, Monitor: 1}); tally != want {
		t.Errorf("tally %+v, want %+v", tally, want)
	}

	all, _ := s.Events(timeline.Query{})
	got := map[int64]string{}
	for _, r := range all {
		got[r.Event.DeviceSeq] = r.Outcome() + " " + r.Label()
	}
	want := map[int64]string{1: "auto AUTO", 2: "ask ASKED", 3: "deny BLOCKED", 4: "would WOULD DENY", 5: "config CONFIG", 6: "allow ALLOWED"}
	for seq, w := range want {
		if got[seq] != w {
			t.Errorf("event %d: %q, want %q", seq, got[seq], w)
		}
	}
	kinds := map[int64]string{}
	for _, r := range all {
		kinds[r.Event.DeviceSeq] = r.Kind()
	}
	if kinds[1] != "Shell" || kinds[5] != "Config" {
		t.Errorf("kinds %v", kinds)
	}
	if tgt := all[1].Target("/home/me"); tgt != "~/.claude/settings.json" {
		t.Errorf("config target %q", tgt)
	}
}

func TestSessionSummaries(t *testing.T) {
	s, _ := open(t)
	now := time.Now()
	a, _ := s.Session("claude_code", "native-a", "github.com/acme/api", now.Add(-time.Hour))
	b, _ := s.Session("cursor", "native-b", "", now)
	s.Session("claude_code", "privometry-file-watcher", "", now) // bookkeeping, left out
	for i, v := range []contract.Verdict{contract.VerdictAllow, contract.VerdictAsk, contract.VerdictDeny} {
		ev := event(a.ID)
		ev.Decision.Verdict = v
		ev.Decision.LatencyMs = float64(i + 1)
		s.Append(ev, "x")
	}
	s.Append(&events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypePrompt,
		OccurredAt: contract.At(now), Device: events.Device{DeviceID: "dev_x", OS: "macos"},
		Agent:     &events.Agent{Product: contract.AgentProductClaudeCode, SessionID: a.ID},
		Prompt:    &events.Prompt{Fingerprint: "hmac-sha256:" + strings.Repeat("a", 64), Characters: 12},
		Redaction: map[string]contract.PrivacyLevel{}}, "Query submitted (12 characters)")
	s.MarkInjected(a.ID)
	ss, err := s.Sessions(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 2 || ss[0].ID != b.ID {
		t.Fatalf("sessions %+v, want two, most recent first", ss)
	}
	got := ss[1]
	if got.Actions != 3 || got.Prompts != 1 || got.Asked != 1 || got.Blocked != 1 || !got.InjectionSeen || got.Repo != "github.com/acme/api" {
		t.Errorf("session %+v", got)
	}
	if tally, _ := s.Tally(now.Add(-2 * time.Hour)); tally.AvgLatencyMs != 2 {
		t.Errorf("average latency %v", tally.AvgLatencyMs)
	}
}
