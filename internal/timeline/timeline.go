// Package timeline is the local SQLite store: every event the sensor records,
// per-session state, and small key-value state such as the device ID and the
// device_seq counter. Only the daemon opens it; the hook client never does.
package timeline

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/events"
)

// Store is an open timeline database.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	CREATE TABLE events (
		event_id TEXT PRIMARY KEY,
		device_seq INTEGER NOT NULL UNIQUE,
		occurred_at TEXT NOT NULL,
		type TEXT NOT NULL,
		agent_product TEXT,
		session_id TEXT,
		repo_remote TEXT,
		action_kind TEXT,
		verdict TEXT,
		risk TEXT,
		rule_ids TEXT,
		target_clear TEXT,
		payload TEXT NOT NULL
	);
	CREATE INDEX events_time ON events (occurred_at);
	CREATE INDEX events_session ON events (session_id, occurred_at);
	CREATE INDEX events_agent ON events (agent_product, occurred_at);
	CREATE INDEX events_repo ON events (repo_remote, occurred_at);
	CREATE TABLE sessions (
		session_id TEXT PRIMARY KEY,
		native_session_id TEXT NOT NULL,
		agent_product TEXT NOT NULL,
		repo_remote TEXT,
		started_at TEXT NOT NULL,
		last_event_at TEXT NOT NULL,
		ended_at TEXT,
		untrusted_input_seen INTEGER NOT NULL DEFAULT 0,
		untrusted_sources TEXT NOT NULL DEFAULT '[]',
		UNIQUE (agent_product, native_session_id)
	);`,
	`CREATE TABLE config_hashes (
		path TEXT PRIMARY KEY,
		tier TEXT NOT NULL,
		agent_product TEXT NOT NULL,
		sha256 TEXT NOT NULL,
		privometry_hook INTEGER NOT NULL DEFAULT 0,
		observed_at TEXT NOT NULL
	);`,
	// Content scanning: sessions that read injected instructions, and memory
	// files among the hashed files, with who last changed each one.
	`ALTER TABLE sessions ADD COLUMN injection_seen INTEGER NOT NULL DEFAULT 0;
	ALTER TABLE config_hashes ADD COLUMN kind TEXT NOT NULL DEFAULT 'config';
	ALTER TABLE config_hashes ADD COLUMN changed_by TEXT NOT NULL DEFAULT '';`,
	// Memory file snapshots (PRD SCAN-14): each version the daemon saw, with
	// its content stored once per digest. Local only; never uploaded.
	`CREATE TABLE memory_blobs (sha256 TEXT PRIMARY KEY, content BLOB NOT NULL);
	CREATE TABLE memory_versions (
		version_id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT NOT NULL,
		agent_product TEXT NOT NULL,
		tier TEXT NOT NULL,
		sha256 TEXT NOT NULL,
		size INTEGER NOT NULL,
		observed_at TEXT NOT NULL,
		changed_by TEXT NOT NULL,
		findings INTEGER NOT NULL,
		restored_from INTEGER
	);
	CREATE INDEX memory_versions_path ON memory_versions (path, version_id);`,
	// Watched files that turn an agent's hooks off (hooks_disabled).
	`ALTER TABLE config_hashes ADD COLUMN hooks_off INTEGER NOT NULL DEFAULT 0;`,
}

// Open opens or creates the database at path, readable only by the user.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; SQLite serializes writes anyway
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("timeline: %w", err)
	}
	return s, nil
}

// OpenReadOnly opens an existing database for reading only, for the CLI when
// the daemon is not running. It never migrates.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// State returns a state value, or "" when unset.
func (s *Store) State(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetState stores a state value.
func (s *Store) SetState(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// DeviceID returns this device's ID, creating it on first use. Free-tier IDs
// stay local; enrollment (P2) may replace it.
func (s *Store) DeviceID() (string, error) {
	id, err := s.State("device_id")
	if err != nil || id != "" {
		return id, err
	}
	id = contract.NewID("dev")
	return id, s.SetState("device_id", id)
}

// Append assigns the event the next device_seq and stores it in one
// transaction, so the sequence has no gaps unless rows are deleted.
// targetClear is the local presentation target after the daemon has applied
// its local-capture policy. It never leaves the device.
func (s *Store) Append(ev *events.Event, targetClear string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var seq int64
	switch err := tx.QueryRow(`SELECT value FROM state WHERE key = 'device_seq'`).Scan(&seq); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	}
	seq++
	if _, err := tx.Exec(`INSERT INTO state (key, value) VALUES ('device_seq', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.FormatInt(seq, 10)); err != nil {
		return err
	}
	ev.DeviceSeq = seq
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	var agent, session, kind, verdict, risk, ruleIDs, remote string
	if ev.Agent != nil {
		agent, session = string(ev.Agent.Product), ev.Agent.SessionID
	}
	if ev.Repo != nil {
		remote = ev.Repo.Remote
	}
	if ev.Action != nil {
		kind, risk = string(ev.Action.Kind), string(ev.Action.Risk)
	}
	if ev.Decision != nil {
		verdict = string(ev.Decision.Verdict)
		ids := ev.Decision.RuleIDs
		if ids == nil {
			ids = []string{}
		}
		b, _ := json.Marshal(ids)
		ruleIDs = string(b)
	}
	_, err = tx.Exec(`INSERT INTO events (event_id, device_seq, occurred_at, type, agent_product, session_id, repo_remote,
		action_kind, verdict, risk, rule_ids, target_clear, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.EventID, seq, ev.OccurredAt.String(), string(ev.Type), agent, session, remote, kind, verdict, risk, ruleIDs, targetClear, string(payload))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Row is one stored event.
type Row struct {
	Event       events.Event `json:"event"`
	TargetClear string       `json:"target_clear,omitempty"`
}

// Query selects events, newest first, or oldest first after AfterSeq (for
// following new events).
type Query struct {
	Agent    string    `json:"agent,omitempty"`
	Session  string    `json:"session,omitempty"`
	Repo     string    `json:"repo,omitempty"`
	Verdict  string    `json:"verdict,omitempty"` // one verdict, or several joined by commas
	Type     string    `json:"type,omitempty"`
	Search   string    `json:"search,omitempty"` // substring of the target or a rule ID
	Since    time.Time `json:"since,omitzero"`
	AfterSeq int64     `json:"after_seq,omitempty"`
	// BeforeSeq pages back: only events older than this device_seq.
	BeforeSeq int64 `json:"before_seq,omitempty"`
	Limit     int   `json:"limit,omitempty"`
}

// Events returns stored events matching q.
func (s *Store) Events(q Query) ([]Row, error) {
	sqlText := `SELECT payload, COALESCE(target_clear, '') FROM events WHERE 1 = 1`
	var args []any
	add := func(clause string, v any) {
		sqlText += " AND " + clause
		args = append(args, v)
	}
	if q.Agent != "" {
		add("agent_product = ?", q.Agent)
	}
	if q.Session != "" {
		add("session_id = ?", q.Session)
	}
	if q.Repo != "" {
		add("repo_remote = ?", q.Repo)
	}
	if q.Verdict != "" {
		vs := strings.Split(q.Verdict, ",")
		sqlText += " AND verdict IN (?" + strings.Repeat(", ?", len(vs)-1) + ")" //nolint:gosec // only ? placeholders are concatenated; values are bound
		for _, v := range vs {
			args = append(args, strings.TrimSpace(v))
		}
	}
	if q.Type != "" {
		add("type = ?", q.Type)
	}
	if q.Search != "" {
		add("instr(lower(COALESCE(target_clear, '') || ' ' || COALESCE(rule_ids, '')), lower(?)) > 0", q.Search)
	}
	if q.AfterSeq > 0 {
		add("device_seq > ?", q.AfterSeq)
	}
	if q.BeforeSeq > 0 {
		add("device_seq < ?", q.BeforeSeq)
	}
	if !q.Since.IsZero() {
		add("occurred_at >= ?", contract.At(q.Since).String())
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	order := "DESC"
	if q.AfterSeq > 0 {
		order = "ASC"
	}
	sqlText += " ORDER BY device_seq " + order + " LIMIT ?"
	args = append(args, q.Limit)
	rows, err := s.db.Query(sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var payload string
		var r Row
		if err := rows.Scan(&payload, &r.TargetClear); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(payload), &r.Event); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Backlog is how many events, and how many bytes of them, come after a
// device_seq, and when the oldest of them occurred.
type Backlog struct {
	Events int
	Bytes  int64
	Oldest time.Time
}

// BacklogAfter reports the events after afterSeq, such as those not uploaded yet.
func (s *Store) BacklogAfter(afterSeq int64) (Backlog, error) {
	var b Backlog
	var oldest sql.NullString
	err := s.db.QueryRow(`SELECT count(*), COALESCE(sum(length(payload)), 0), min(occurred_at) FROM events WHERE device_seq > ?`, afterSeq).
		Scan(&b.Events, &b.Bytes, &oldest)
	if err != nil {
		return b, err
	}
	if oldest.Valid {
		b.Oldest, _ = time.Parse(time.RFC3339Nano, oldest.String)
	}
	return b, nil
}

// LastSeq is the highest device_seq stored; 0 when there are no events.
func (s *Store) LastSeq() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COALESCE(max(device_seq), 0) FROM events`).Scan(&n)
	return n, err
}

// Prune deletes events older than eventsBefore and sessions idle since
// sessionsBefore. It returns how many events it removed.
func (s *Store) Prune(eventsBefore, sessionsBefore time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM events WHERE occurred_at < ?`, contract.At(eventsBefore).String())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.db.Exec(`DELETE FROM sessions WHERE last_event_at < ?`, contract.At(sessionsBefore).String())
	return n, err
}

// Session is the stored state of one agent session.
type Session struct {
	ID                 string
	Native             string
	Agent              string
	Repo               string
	StartedAt          time.Time
	UntrustedInputSeen bool
	UntrustedSources   []string
	InjectionSeen      bool
}

// Session returns the session for an agent's own session ID, creating it
// when new. now becomes its last activity time.
func (s *Store) Session(agent, native, repo string, now time.Time) (*Session, error) {
	ts := contract.At(now).String()
	_, err := s.db.Exec(`INSERT INTO sessions (session_id, native_session_id, agent_product, repo_remote, started_at, last_event_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(agent_product, native_session_id) DO UPDATE SET last_event_at = excluded.last_event_at`,
		contract.NewID("ses"), native, agent, repo, ts, ts)
	if err != nil {
		return nil, err
	}
	var sess Session
	var untrusted, injected int
	var sources, started string
	err = s.db.QueryRow(`SELECT session_id, native_session_id, agent_product, COALESCE(repo_remote, ''), started_at, untrusted_input_seen, untrusted_sources, injection_seen
		FROM sessions WHERE agent_product = ? AND native_session_id = ?`, agent, native).
		Scan(&sess.ID, &sess.Native, &sess.Agent, &sess.Repo, &started, &untrusted, &sources, &injected)
	if err != nil {
		return nil, err
	}
	sess.UntrustedInputSeen, sess.InjectionSeen = untrusted != 0, injected != 0
	sess.StartedAt, _ = time.Parse(time.RFC3339, started)
	if err := json.Unmarshal([]byte(sources), &sess.UntrustedSources); err != nil {
		return nil, err
	}
	return &sess, nil
}

// MarkUntrusted records that untrusted content entered a session.
func (s *Store) MarkUntrusted(sessionID, source string) error {
	var sources string
	if err := s.db.QueryRow(`SELECT untrusted_sources FROM sessions WHERE session_id = ?`, sessionID).Scan(&sources); err != nil {
		return err
	}
	var list []string
	if err := json.Unmarshal([]byte(sources), &list); err != nil {
		return err
	}
	found := false
	for _, x := range list {
		found = found || x == source
	}
	if !found {
		list = append(list, source)
	}
	b, _ := json.Marshal(list)
	_, err := s.db.Exec(`UPDATE sessions SET untrusted_input_seen = 1, untrusted_sources = ? WHERE session_id = ?`, string(b), sessionID)
	return err
}

// MarkInjected records that a session read content flagged as injected
// instructions; it stays marked for the rest of the session.
func (s *Store) MarkInjected(sessionID string) error {
	_, err := s.db.Exec(`UPDATE sessions SET injection_seen = 1 WHERE session_id = ?`, sessionID)
	return err
}

// EndSession marks a session ended.
func (s *Store) EndSession(sessionID string, at time.Time) error {
	_, err := s.db.Exec(`UPDATE sessions SET ended_at = ? WHERE session_id = ?`, contract.At(at).String(), sessionID)
	return err
}

// AgentActivity is how often an agent's hooks reached the daemon.
type AgentActivity struct {
	Agent    string    `json:"agent"`
	LastCall time.Time `json:"last_call"`
	Calls    int       `json:"calls"`
}

// Activity returns, per agent, the time of its last decision and how many
// decisions are stored.
func (s *Store) Activity() ([]AgentActivity, error) {
	rows, err := s.db.Query(`SELECT agent_product, MAX(occurred_at), COUNT(*) FROM events
		WHERE type IN ('action', 'fail_mode') AND agent_product <> '' GROUP BY agent_product ORDER BY agent_product`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentActivity
	for rows.Next() {
		var a AgentActivity
		var last string
		if err := rows.Scan(&a.Agent, &last, &a.Calls); err != nil {
			return nil, err
		}
		a.LastCall, _ = time.Parse(time.RFC3339, last)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Tally counts the agent actions decided since a time.
type Tally struct {
	Actions  int `json:"actions"`
	Auto     int `json:"auto"`    // allowed by risk, without a rule
	Asked    int `json:"asked"`   // the developer was asked
	Blocked  int `json:"blocked"` // denied, including closed fail modes
	Monitor  int `json:"monitor"` // a monitor rule would have asked or denied
	FailMode int `json:"fail_mode"`
	// AvgLatencyMs is the mean decision time of the actions.
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// Tally counts actions and fail-mode decisions since a time.
func (s *Store) Tally(since time.Time) (Tally, error) {
	var t Tally
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		COALESCE(SUM(type = 'action' AND json_extract(payload, '$.decision.source') = 'auto_approve' AND verdict = 'allow'), 0),
		COALESCE(SUM(verdict = 'ask'), 0),
		COALESCE(SUM(verdict = 'deny'), 0),
		COALESCE(SUM(json_extract(payload, '$.decision.mode') = 'monitor'), 0),
		COALESCE(SUM(type = 'fail_mode'), 0),
		COALESCE(AVG(CASE WHEN type = 'action' THEN json_extract(payload, '$.decision.latency_ms') END), 0)
		FROM events WHERE type IN ('action', 'fail_mode') AND occurred_at >= ?`, contract.At(since).String()).
		Scan(&t.Actions, &t.Auto, &t.Asked, &t.Blocked, &t.Monitor, &t.FailMode, &t.AvgLatencyMs)
	return t, err
}

// SessionSummary is one agent session with its decision counts.
type SessionSummary struct {
	ID            string    `json:"id"`
	Agent         string    `json:"agent"`
	Repo          string    `json:"repo,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	LastEventAt   time.Time `json:"last_event_at"`
	Ended         bool      `json:"ended"`
	Actions       int       `json:"actions"`
	Prompts       int       `json:"prompts"`
	Asked         int       `json:"asked"`
	Blocked       int       `json:"blocked"`
	Findings      int       `json:"findings"`
	Untrusted     bool      `json:"untrusted_input_seen"`
	InjectionSeen bool      `json:"injection_seen"`
}

// Sessions returns agent sessions, most recently active first, leaving out
// the file watcher's bookkeeping sessions.
func (s *Store) Sessions(limit int) ([]SessionSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT s.session_id, s.agent_product, COALESCE(s.repo_remote, ''), s.started_at, s.last_event_at,
		s.ended_at IS NOT NULL, s.untrusted_input_seen, s.injection_seen,
		COALESCE(SUM(e.type = 'action'), 0), COALESCE(SUM(e.type = 'prompt'), 0), COALESCE(SUM(e.type = 'action' AND e.verdict = 'ask'), 0),
		COALESCE(SUM(e.type IN ('action', 'fail_mode') AND e.verdict = 'deny'), 0), COALESCE(SUM(e.type = 'content_finding'), 0)
		FROM sessions s LEFT JOIN events e ON e.session_id = s.session_id
		WHERE s.native_session_id <> 'privometry-file-watcher'
		GROUP BY s.session_id ORDER BY s.last_event_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionSummary{}
	for rows.Next() {
		var x SessionSummary
		var started, last string
		if err := rows.Scan(&x.ID, &x.Agent, &x.Repo, &started, &last, &x.Ended, &x.Untrusted, &x.InjectionSeen,
			&x.Actions, &x.Prompts, &x.Asked, &x.Blocked, &x.Findings); err != nil {
			return nil, err
		}
		x.StartedAt, _ = time.Parse(time.RFC3339, started)
		x.LastEventAt, _ = time.Parse(time.RFC3339, last)
		out = append(out, x)
	}
	return out, rows.Err()
}

// ConfigHash is the last observed state of one watched config file. SHA256 is
// "" when the file did not exist.
type ConfigHash struct {
	Path, Tier, Agent, SHA256 string
	PrivometryHook            bool
	HooksOff                  bool   // the file turns the agent's hooks off
	Kind                      string // config or memory; empty means config
	ChangedBy                 string // memory files: person, agent or "" when unknown
	ObservedAt                time.Time
}

// ConfigHashes returns every watched file's last state, by path.
func (s *Store) ConfigHashes() (map[string]ConfigHash, error) {
	rows, err := s.db.Query(`SELECT path, tier, agent_product, sha256, privometry_hook, hooks_off, kind, changed_by, observed_at FROM config_hashes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ConfigHash{}
	for rows.Next() {
		var h ConfigHash
		var hook, off int
		var observed string
		if err := rows.Scan(&h.Path, &h.Tier, &h.Agent, &h.SHA256, &hook, &off, &h.Kind, &h.ChangedBy, &observed); err != nil {
			return nil, err
		}
		var err error
		if h.ObservedAt, err = time.Parse(time.RFC3339Nano, observed); err != nil {
			return nil, fmt.Errorf("timeline: config hash %q has invalid observed_at: %w", h.Path, err)
		}
		h.PrivometryHook, h.HooksOff = hook != 0, off != 0
		out[h.Path] = h
	}
	return out, rows.Err()
}

// SetConfigHash stores a watched file's state.
func (s *Store) SetConfigHash(h ConfigHash, at time.Time) error {
	hook, off := 0, 0
	if h.PrivometryHook {
		hook = 1
	}
	if h.HooksOff {
		off = 1
	}
	if h.Kind == "" {
		h.Kind = "config"
	}
	_, err := s.db.Exec(`INSERT INTO config_hashes (path, tier, agent_product, sha256, privometry_hook, hooks_off, observed_at, kind, changed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET tier = excluded.tier, agent_product = excluded.agent_product, sha256 = excluded.sha256,
		privometry_hook = excluded.privometry_hook, hooks_off = excluded.hooks_off, observed_at = excluded.observed_at, kind = excluded.kind, changed_by = excluded.changed_by`,
		h.Path, h.Tier, h.Agent, h.SHA256, hook, off, contract.At(at).String(), h.Kind, h.ChangedBy)
	return err
}

// MemoryVersion is one version of a memory or instruction file. SHA256 is
// empty for a version where the file was deleted.
type MemoryVersion struct {
	ID           int64     `json:"version"`
	Path         string    `json:"path"`
	Agent        string    `json:"agent"`
	Tier         string    `json:"tier"`
	SHA256       string    `json:"sha256,omitempty"`
	Size         int64     `json:"size"`
	ObservedAt   time.Time `json:"observed_at"`
	ChangedBy    string    `json:"changed_by"` // first, person, agent or restore
	Findings     int       `json:"findings"`   // content findings when it was seen
	RestoredFrom int64     `json:"restored_from,omitempty"`
}

// AddMemoryVersion records a version and keeps its content, once per digest.
func (s *Store) AddMemoryVersion(v MemoryVersion, content []byte) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if v.SHA256 != "" {
		if _, err := tx.Exec(`INSERT INTO memory_blobs (sha256, content) VALUES (?, ?) ON CONFLICT(sha256) DO NOTHING`, v.SHA256, content); err != nil {
			return 0, err
		}
	}
	var restored any
	if v.RestoredFrom != 0 {
		restored = v.RestoredFrom
	}
	res, err := tx.Exec(`INSERT INTO memory_versions (path, agent_product, tier, sha256, size, observed_at, changed_by, findings, restored_from)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, v.Path, v.Agent, v.Tier, v.SHA256, v.Size, contract.At(v.ObservedAt).String(), v.ChangedBy, v.Findings, restored)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

const memoryColumns = `version_id, path, agent_product, tier, sha256, size, observed_at, changed_by, findings, COALESCE(restored_from, 0)`

func scanMemoryVersion(sc interface{ Scan(...any) error }) (MemoryVersion, error) {
	var v MemoryVersion
	var observed string
	if err := sc.Scan(&v.ID, &v.Path, &v.Agent, &v.Tier, &v.SHA256, &v.Size, &observed, &v.ChangedBy, &v.Findings, &v.RestoredFrom); err != nil {
		return v, err
	}
	var err error
	v.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	return v, err
}

// MemoryVersions returns a file's versions, newest first.
func (s *Store) MemoryVersions(path string) ([]MemoryVersion, error) {
	rows, err := s.db.Query(`SELECT `+memoryColumns+` FROM memory_versions WHERE path = ? ORDER BY version_id DESC`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MemoryVersion
	for rows.Next() {
		v, err := scanMemoryVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestMemoryVersions returns the newest version of every file, with how
// many versions each has.
func (s *Store) LatestMemoryVersions() ([]MemoryVersion, map[string]int, error) {
	rows, err := s.db.Query(`SELECT ` + memoryColumns + ` FROM memory_versions WHERE version_id IN
		(SELECT MAX(version_id) FROM memory_versions GROUP BY path) ORDER BY path`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []MemoryVersion
	for rows.Next() {
		v, err := scanMemoryVersion(rows)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	counts := map[string]int{}
	crows, err := s.db.Query(`SELECT path, COUNT(*) FROM memory_versions GROUP BY path`)
	if err != nil {
		return nil, nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var p string
		var n int
		if err := crows.Scan(&p, &n); err != nil {
			return nil, nil, err
		}
		counts[p] = n
	}
	return out, counts, crows.Err()
}

// MemoryVersion returns one version and its content (nil for a deletion).
func (s *Store) MemoryVersion(id int64) (MemoryVersion, []byte, error) {
	v, err := scanMemoryVersion(s.db.QueryRow(`SELECT `+memoryColumns+` FROM memory_versions WHERE version_id = ?`, id))
	if err != nil {
		return v, nil, err
	}
	if v.SHA256 == "" {
		return v, nil, nil
	}
	var content []byte
	err = s.db.QueryRow(`SELECT content FROM memory_blobs WHERE sha256 = ?`, v.SHA256).Scan(&content)
	return v, content, err
}

// PruneMemory keeps, per file, the newest keep versions and every version
// newer than since, then drops content no version refers to.
func (s *Store) PruneMemory(keep int, since time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM memory_versions WHERE observed_at < ? AND version_id NOT IN (
		SELECT version_id FROM (SELECT version_id, ROW_NUMBER() OVER (PARTITION BY path ORDER BY version_id DESC) AS n FROM memory_versions) WHERE n <= ?)`,
		contract.At(since).String(), keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = s.db.Exec(`DELETE FROM memory_blobs WHERE sha256 NOT IN (SELECT sha256 FROM memory_versions)`)
	return n, err
}
