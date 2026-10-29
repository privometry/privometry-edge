// Package webui serves the local timeline in a browser: a static page and a
// small read-only JSON API over the timeline database.
//
// The page shows full commands, which never leave the device, so the server
// is locked to the user who started it:
//
//   - it listens on 127.0.0.1 only;
//   - a random token, printed in the URL, is swapped on first load for a
//     SameSite=Strict, HttpOnly cookie, and every request needs one of them;
//   - the Host header must name the loopback address and port, which stops
//     DNS rebinding;
//   - cross-site requests and every method but GET and HEAD are refused;
//   - a strict Content-Security-Policy allows only the page's own files,
//     fonts included.
package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// Source is the timeline the page reads.
type Source interface {
	Events(timeline.Query) ([]timeline.Row, error)
	Tally(since time.Time) (timeline.Tally, error)
	Activity() ([]timeline.AgentActivity, error)
	Sessions(limit int) ([]timeline.SessionSummary, error)
}

// View is a page section the CLI computes, such as a scan or the policy
// layers, served as JSON at /api/<name> and cached for TTL.
type View struct {
	TTL time.Duration
	Get func() (any, error)
}

// Daemon describes the running daemon, for the page's header.
type Daemon struct {
	Running bool      `json:"running"`
	Version string    `json:"version,omitempty"`
	Started time.Time `json:"started,omitzero"`
	// Outdated is set when the daemon is an older build than this CLI.
	Outdated bool `json:"outdated,omitempty"`
}

// Config sets up a server.
type Config struct {
	// Open opens the timeline. It is called until it succeeds, so the page
	// works before the daemon has recorded anything.
	Open func() (Source, error)
	// Daemon reports the daemon's state; nil means unknown.
	Daemon func() Daemon
	// Home is shown as ~ in targets.
	Home string
	// Assets holds index.html and the files it loads.
	Assets fs.FS
	// Views are the computed sections, by name (scan, policy, device, agents).
	Views map[string]View
	// Host and User name this machine and person in the page header.
	Host, User string
	// Now is the clock (tests set it).
	Now func() time.Time
}

// Server is one timeline server.
type Server struct {
	cfg   Config
	token string
	port  int

	mu    sync.Mutex
	src   Source
	cache map[string]cached
}

type cached struct {
	at   time.Time
	data []byte
}

// New creates a server with a fresh random token.
func New(cfg Config) (*Server, error) {
	if cfg.Open == nil || cfg.Assets == nil {
		return nil, errors.New("webui: Open and Assets are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, token: hex.EncodeToString(b), cache: map[string]cached{}}, nil
}

// Token is the secret the first request must carry.
func (s *Server) Token() string { return s.token }

// URL is the address to open, for a server listening on port.
func (s *Server) URL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d/?token=%s", port, s.token)
}

// Handler serves the page for a listener on 127.0.0.1:port.
func (s *Server) Handler(port int) http.Handler {
	s.port = port
	static := http.FileServerFS(s.cfg.Assets)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/events", s.events)
	mux.HandleFunc("/api/summary", s.summary)
	mux.HandleFunc("/api/sessions", s.sessions)
	mux.HandleFunc("/api/view/", s.serveView)
	mux.Handle("/", static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if !s.allowedHost(r.Host) {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
			http.Error(w, "cross-site request", http.StatusForbidden)
			return
		}
		if tok := r.URL.Query().Get("token"); tok != "" {
			if !s.validToken(tok) {
				http.Error(w, "wrong token", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}) //nolint:gosec // HttpOnly and SameSite=Strict; Secure cannot work on http://127.0.0.1
			// Drop the token from the address bar. The page routes by fragment, so "/" is always right, and a path
			// like //example.com cannot turn this into a redirect off the machine.
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !s.authorized(r) {
			http.Error(w, "Open the link that privometry timeline --web printed.", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) allowedHost(host string) bool {
	p := strconv.Itoa(s.port)
	return host == "127.0.0.1:"+p || host == "localhost:"+p
}

func (s *Server) validToken(tok string) bool {
	return subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
}

// cookieName includes the port: cookies are not isolated by port, and two
// timelines may run at once.
func (s *Server) cookieName() string { return "privometry_timeline_" + strconv.Itoa(s.port) }

func (s *Server) authorized(r *http.Request) bool {
	if c, err := r.Cookie(s.cookieName()); err == nil && s.validToken(c.Value) {
		return true
	}
	if a, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && s.validToken(a) {
		return true
	}
	return false
}

func (s *Server) source() (Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.src != nil {
		return s.src, nil
	}
	src, err := s.cfg.Open()
	if err != nil {
		return nil, err
	}
	s.src = src
	return src, nil
}

// Row is one event as the page shows it.
type Row struct {
	Seq       int64    `json:"seq"`
	ID        string   `json:"id"`
	At        string   `json:"at"`
	Type      string   `json:"type"`
	Agent     string   `json:"agent,omitempty"`
	Outcome   string   `json:"outcome"`
	Label     string   `json:"label"`
	What      string   `json:"what"`
	Why       string   `json:"why,omitempty"`
	Message   string   `json:"message,omitempty"`
	Rules     []string `json:"rules,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	KindLabel string   `json:"kind_label,omitempty"` // Shell, Read, Write, MCP, Config, Finding, …
	Tool      string   `json:"tool,omitempty"`
	Risk      string   `json:"risk,omitempty"`
	LatencyMs *float64 `json:"latency_ms,omitempty"`
	Repo      string   `json:"repo,omitempty"`
	Untrusted bool     `json:"untrusted,omitempty"`
	// Event is the stored event, with its target redacted as it would be
	// uploaded.
	Event events.Event `json:"event"`
}

func (s *Server) view(r timeline.Row) Row {
	e := r.Event
	v := Row{Seq: e.DeviceSeq, ID: e.EventID, At: e.OccurredAt.String(), Type: string(e.Type), Agent: r.AgentName(),
		Outcome: r.Outcome(), Label: r.Label(), What: r.Target(s.cfg.Home), Why: r.Why(), Message: r.Message(), Event: e,
		KindLabel: r.Kind()}
	if e.Action != nil {
		v.Kind, v.Tool, v.Risk = string(e.Action.Kind), e.Action.ToolName, string(e.Action.Risk)
	}
	if e.Decision != nil {
		v.Rules = e.Decision.RuleIDs
		if e.Type == "action" {
			ms := e.Decision.LatencyMs
			v.LatencyMs = &ms
		}
	}
	if e.Repo != nil {
		v.Repo = e.Repo.Remote
	}
	if e.Context != nil {
		v.Untrusted = e.Context.UntrustedInputSeen
	}
	return v
}

// showVerdicts maps the page's filter to stored verdicts.
var showVerdicts = map[string]string{"": "", "all": "", "exc": "ask,deny", "ask": "ask", "deny": "deny"}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query()
	verdict, ok := showVerdicts[p.Get("show")]
	if !ok {
		http.Error(w, "show must be all, exc, ask or deny", http.StatusBadRequest)
		return
	}
	q := timeline.Query{Agent: p.Get("agent"), Type: p.Get("type"), Search: p.Get("search"), Verdict: verdict, Limit: 100}
	for name, dst := range map[string]*int64{"after_seq": &q.AfterSeq, "before_seq": &q.BeforeSeq} {
		if v := p.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				http.Error(w, "bad "+name, http.StatusBadRequest)
				return
			}
			*dst = n
		}
	}
	if v := p.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			http.Error(w, "limit must be 1 to 500", http.StatusBadRequest)
			return
		}
		q.Limit = n
	}
	// One extra row tells the page whether older events remain.
	limit := q.Limit
	if q.AfterSeq == 0 {
		q.Limit++
	}
	out := struct {
		Rows []Row `json:"rows"`
		More bool  `json:"more"`
	}{Rows: []Row{}}
	src, err := s.source()
	if err != nil {
		writeJSON(w, out) // no database yet: nothing recorded
		return
	}
	rows, err := src.Events(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(rows) > limit {
		rows, out.More = rows[:limit], true
	}
	for _, row := range rows {
		out.Rows = append(out.Rows, s.view(row))
	}
	writeJSON(w, out)
}

// Summary is the page's header: today's tally, each agent's activity, the
// daemon's state, and who and where this is.
type Summary struct {
	Tally  timeline.Tally           `json:"tally"`
	Agents []timeline.AgentActivity `json:"agents"`
	Daemon *Daemon                  `json:"daemon,omitempty"`
	Empty  bool                     `json:"empty"` // no database yet
	Host   string                   `json:"host,omitempty"`
	User   string                   `json:"user,omitempty"`
}

func (s *Server) summary(w http.ResponseWriter, _ *http.Request) {
	out := Summary{Host: s.cfg.Host, User: s.cfg.User}
	if s.cfg.Daemon != nil {
		d := s.cfg.Daemon()
		out.Daemon = &d
	}
	src, err := s.source()
	if err != nil {
		out.Empty, out.Agents = true, []timeline.AgentActivity{}
		writeJSON(w, out)
		return
	}
	now := s.cfg.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if out.Tally, err = src.Tally(midnight); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if out.Agents, err = src.Activity(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if out.Agents == nil {
		out.Agents = []timeline.AgentActivity{}
	}
	writeJSON(w, out)
}

func (s *Server) sessions(w http.ResponseWriter, _ *http.Request) {
	src, err := s.source()
	if err != nil {
		writeJSON(w, []timeline.SessionSummary{})
		return
	}
	out, err := src.Sessions(100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, out)
}

// serveView serves /api/view/<name> from its cache, recomputing it when stale or
// when ?fresh=1 asks for it (the Scan page's "Scan now").
func (s *Server) serveView(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/view/")
	v, ok := s.cfg.Views[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	c, hit := s.cache[name]
	s.mu.Unlock()
	if !hit || r.URL.Query().Get("fresh") == "1" || s.cfg.Now().Sub(c.at) > v.TTL {
		data, err := v.Get()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		raw, err := json.Marshal(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c = cached{at: s.cfg.Now(), data: raw}
		s.mu.Lock()
		s.cache[name] = c
		s.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(c.data)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
