package webui_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/timeline"
	"github.com/privometry/privometry-edge/internal/webui"
	timelineweb "github.com/privometry/privometry-edge/ui/timeline-web"
)

const port = 4747

func newServer(t *testing.T, src webui.Source) (*webui.Server, http.Handler) {
	t.Helper()
	srv, err := webui.New(webui.Config{
		Open: func() (webui.Source, error) {
			if src == nil {
				return nil, errors.New("no database")
			}
			return src, nil
		},
		Daemon: func() webui.Daemon { return webui.Daemon{Running: true, Version: "dev"} },
		Home:   "/Users/me",
		Assets: fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>t</title>")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(port)
}

func do(h http.Handler, method, target string, mut func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "127.0.0.1:4747"
	if mut != nil {
		mut(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func cookie(srv *webui.Server) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "privometry_timeline_4747", Value: srv.Token()})
	}
}

func TestAccessControl(t *testing.T) {
	srv, h := newServer(t, nil)
	cases := []struct {
		name   string
		method string
		target string
		mut    func(*http.Request)
		want   int
	}{
		{"no token", "GET", "/", nil, http.StatusUnauthorized},
		{"no token on the API", "GET", "/api/events", nil, http.StatusUnauthorized},
		{"wrong token", "GET", "/?token=nope", nil, http.StatusUnauthorized},
		{"wrong cookie", "GET", "/", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "privometry_timeline_4747", Value: "nope"}) }, http.StatusUnauthorized},
		{"another port's cookie", "GET", "/", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "privometry_timeline_1", Value: srv.Token()}) }, http.StatusUnauthorized},
		{"rebound host name", "GET", "/?token=" + srv.Token(), func(r *http.Request) { r.Host = "evil.example:4747" }, http.StatusMisdirectedRequest},
		{"other port in host", "GET", "/", func(r *http.Request) { cookie(srv)(r); r.Host = "127.0.0.1:80" }, http.StatusMisdirectedRequest},
		{"cross-site fetch", "GET", "/api/events", func(r *http.Request) { cookie(srv)(r); r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"POST", "POST", "/api/events", cookie(srv), http.StatusMethodNotAllowed},
		{"cookie", "GET", "/", cookie(srv), http.StatusOK},
		{"localhost host", "GET", "/", func(r *http.Request) { cookie(srv)(r); r.Host = "localhost:4747" }, http.StatusOK},
		{"bearer token", "GET", "/api/summary", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+srv.Token()) }, http.StatusOK},
		{"same-origin fetch", "GET", "/api/events", func(r *http.Request) { cookie(srv)(r); r.Header.Set("Sec-Fetch-Site", "same-origin") }, http.StatusOK},
	}
	for _, c := range cases {
		w := do(h, c.method, c.target, c.mut)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, w.Code, c.want, strings.TrimSpace(w.Body.String()))
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", c.name, csp)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: responses must not be cached", c.name)
		}
	}
}

func TestTokenBecomesCookie(t *testing.T) {
	srv, h := newServer(t, nil)
	w := do(h, "GET", "/?token="+srv.Token(), nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("token must redirect to a clean URL: %d %q", w.Code, w.Header().Get("Location"))
	}
	c := w.Result().Cookies()
	if len(c) != 1 || c[0].Name != "privometry_timeline_4747" || c[0].Value != srv.Token() || !c[0].HttpOnly || c[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie %+v", c)
	}
	if srv.URL(port) != "http://127.0.0.1:4747/?token="+srv.Token() {
		t.Errorf("URL %s", srv.URL(port))
	}
	other, _ := newServer(t, nil)
	if other.Token() == srv.Token() || len(srv.Token()) != 64 {
		t.Error("tokens must be random, 32 bytes")
	}
}

func seeded(t *testing.T) *timeline.Store {
	t.Helper()
	s, err := timeline.Open(filepath.Join(t.TempDir(), "privometry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for i := range 7 {
		ev := &events.Event{Schema: events.EventSchema, EventID: contract.NewID("evt"), Type: events.EventTypeAction,
			OccurredAt: contract.At(time.Now()), Device: events.Device{DeviceID: "dev_x", OS: "macos"},
			Agent:     &events.Agent{Product: contract.AgentProductClaudeCode, SessionID: "ses_A"},
			Action:    &events.Action{Kind: contract.ActionKindShellExec, Risk: contract.RiskLow, Target: "<redacted>"},
			Decision:  &events.Decision{Verdict: contract.VerdictAllow, Source: events.DecisionSourceAutoApprove, LatencyMs: 0.4},
			Context:   &events.Context{UntrustedInputSeen: i == 6},
			Ext:       map[string]any{"x_privometry_reason": "risk low"},
			Redaction: map[string]contract.PrivacyLevel{}}
		target := "ls /Users/me/src"
		if i == 6 {
			ev.Decision.Verdict, ev.Decision.Source, ev.Decision.RuleIDs = contract.VerdictDeny, events.DecisionSourcePolicy, []string{"privometry/core-catastrophic:home-recursive-delete"}
			ev.Ext["x_privometry_message"] = "Privometry blocked deleting your home folder."
			target = "rm -rf /Users/me"
		}
		if i == 5 {
			ev.Agent.Product = contract.AgentProductCursor
		}
		if err := s.Append(ev, target); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

type page struct {
	Rows []webui.Row `json:"rows"`
	More bool        `json:"more"`
}

func get[T any](t *testing.T, h http.Handler, srv *webui.Server, target string) (T, int) {
	t.Helper()
	var v T
	w := do(h, "GET", target, cookie(srv))
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
	}
	return v, w.Code
}

func TestEventsAPI(t *testing.T) {
	srv, h := newServer(t, seeded(t))

	p, _ := get[page](t, h, srv, "/api/events?limit=3")
	if len(p.Rows) != 3 || !p.More || p.Rows[0].Seq != 7 {
		t.Fatalf("first page: %d rows, more %v", len(p.Rows), p.More)
	}
	top := p.Rows[0]
	if top.Outcome != "deny" || top.What != "rm -rf ~" || top.Message == "" || !top.Untrusted ||
		len(top.Rules) != 1 || top.LatencyMs == nil || top.Agent != "claude_code" {
		t.Errorf("row view: %+v", top)
	}
	if top.Event.Action.Target != "<redacted>" {
		t.Error("the raw event must be the stored, redacted one")
	}
	older, _ := get[page](t, h, srv, "/api/events?limit=3&before_seq=5")
	if len(older.Rows) != 3 || older.Rows[0].Seq != 4 || !older.More {
		t.Errorf("before_seq page: %+v", older)
	}
	last, _ := get[page](t, h, srv, "/api/events?limit=3&before_seq=2")
	if len(last.Rows) != 1 || last.More {
		t.Errorf("last page: %d rows, more %v", len(last.Rows), last.More)
	}
	newer, _ := get[page](t, h, srv, "/api/events?after_seq=5")
	if len(newer.Rows) != 2 || newer.Rows[0].Seq != 6 {
		t.Errorf("after_seq returns newer events oldest first: %+v", newer.Rows)
	}
	if exc, _ := get[page](t, h, srv, "/api/events?show=exc"); len(exc.Rows) != 1 {
		t.Errorf("show=exc: %d", len(exc.Rows))
	}
	if cur, _ := get[page](t, h, srv, "/api/events?agent=cursor"); len(cur.Rows) != 1 {
		t.Errorf("agent filter: %d", len(cur.Rows))
	}
	if found, _ := get[page](t, h, srv, "/api/events?search=home-recursive"); len(found.Rows) != 1 {
		t.Errorf("search by rule: %d", len(found.Rows))
	}
	for _, bad := range []string{"show=everything", "limit=0", "limit=9999", "before_seq=x", "after_seq=-1"} {
		if _, code := get[page](t, h, srv, "/api/events?"+bad); code != http.StatusBadRequest {
			t.Errorf("%s: status %d", bad, code)
		}
	}

	sum, _ := get[webui.Summary](t, h, srv, "/api/summary")
	if sum.Tally.Actions != 7 || sum.Tally.Blocked != 1 || sum.Tally.Auto != 6 || len(sum.Agents) != 2 || sum.Daemon == nil || !sum.Daemon.Running {
		t.Errorf("summary %+v", sum)
	}
}

func TestNoDatabaseYet(t *testing.T) {
	srv, h := newServer(t, nil)
	p, code := get[page](t, h, srv, "/api/events")
	if code != http.StatusOK || len(p.Rows) != 0 || p.Rows == nil {
		t.Errorf("events without a database: %d %+v", code, p)
	}
	sum, _ := get[webui.Summary](t, h, srv, "/api/summary")
	if !sum.Empty || sum.Agents == nil {
		t.Errorf("summary without a database: %+v", sum)
	}
}

func TestEmbeddedPage(t *testing.T) {
	srv, err := webui.New(webui.Config{Open: func() (webui.Source, error) { return nil, errors.New("none") }, Assets: timelineweb.Files})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler(port)
	for path, want := range map[string]string{"/": "<script src=\"app.js\"", "/app.js": "textContent", "/style.css": "--block-glyph"} {
		w := do(h, "GET", path, cookie(srv))
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d, missing %q", path, w.Code, want)
		}
	}
	// The CSP forbids inline script and style, so the page must have none.
	w := do(h, "GET", "/", cookie(srv))
	if body := w.Body.String(); strings.Contains(body, "<script>") || strings.Contains(body, "<style") || strings.Contains(body, " style=") || strings.Contains(body, "onclick") {
		t.Error("index.html must not use inline script or style")
	}
	if strings.Contains(do(h, "GET", "/app.js", cookie(srv)).Body.String(), "innerHTML") {
		t.Error("app.js must build the page with textContent, not innerHTML")
	}
	// Every font the stylesheet names ships in the binary, and the policy
	// loads fonts from the page itself only.
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "font-src 'self';") {
		t.Errorf("fonts must come from the page itself: %q", csp)
	}
	urls := regexp.MustCompile(`url\('(fonts/[^']+)'\)`).FindAllStringSubmatch(do(h, "GET", "/style.css", cookie(srv)).Body.String(), -1)
	if len(urls) != 4 {
		t.Errorf("style.css declares %d fonts, want 4", len(urls))
	}
	for _, u := range urls {
		f := do(h, "GET", "/"+u[1], cookie(srv))
		if f.Code != http.StatusOK || f.Header().Get("Content-Type") != "font/woff2" || f.Body.Len() < 10000 {
			t.Errorf("%s: %d %q, %d bytes", u[1], f.Code, f.Header().Get("Content-Type"), f.Body.Len())
		}
	}
}

func TestSessionsAndViews(t *testing.T) {
	calls := 0
	store := seeded(t)
	if _, err := store.Session("claude_code", "native-1", "github.com/acme/api", time.Now()); err != nil {
		t.Fatal(err)
	}
	srv, err := webui.New(webui.Config{
		Open:   func() (webui.Source, error) { return store, nil },
		Assets: fstest.MapFS{"index.html": {Data: []byte("x")}},
		Views: map[string]webui.View{"scan": {TTL: time.Hour, Get: func() (any, error) {
			calls++
			return map[string]int{"run": calls}, nil
		}}},
		Host: "mbp", User: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler(port)
	ss, code := get[[]timeline.SessionSummary](t, h, srv, "/api/sessions")
	if code != 200 || len(ss) != 1 || ss[0].Agent != "claude_code" || ss[0].Repo != "github.com/acme/api" {
		t.Errorf("sessions %d %+v", code, ss)
	}
	first, _ := get[map[string]int](t, h, srv, "/api/view/scan")
	again, _ := get[map[string]int](t, h, srv, "/api/view/scan")
	fresh, _ := get[map[string]int](t, h, srv, "/api/view/scan?fresh=1")
	if first["run"] != 1 || again["run"] != 1 || fresh["run"] != 2 {
		t.Errorf("views must be cached until stale or ?fresh=1: %v %v %v", first, again, fresh)
	}
	if _, code := get[map[string]int](t, h, srv, "/api/view/nope"); code != http.StatusNotFound {
		t.Errorf("unknown view: %d", code)
	}
	if sum, _ := get[webui.Summary](t, h, srv, "/api/summary"); sum.Host != "mbp" || sum.User != "dev" {
		t.Errorf("summary host and user: %+v", sum)
	}
	if w := do(h, "GET", "/api/view/scan", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("views need the cookie: %d", w.Code)
	}
}
