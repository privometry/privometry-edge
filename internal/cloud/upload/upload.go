// Package upload sends the local timeline's events to the cloud (PRD EDGE-28,
// POST /edge/v1/events:batch) in device_seq order, from a cursor kept in the
// timeline, so events recorded while offline go up when the cloud is back.
// Events are stored redacted already; before upload each gets the enrolled
// organization and device, the person the device is enrolled for, and the
// local username hashed with the organization's key. Batches hold at most 500
// events and 1 MB gzip-compressed.
package upload

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/privometry/privometry-oss/internal/cloud"
	"github.com/privometry/privometry-oss/internal/cloud/bundles"
	"github.com/privometry/privometry-oss/internal/cloud/enroll"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/events"
	"github.com/privometry/privometry-oss/internal/keystore"
	"github.com/privometry/privometry-oss/internal/platform"
	"github.com/privometry/privometry-oss/internal/redact"
	"github.com/privometry/privometry-oss/internal/timeline"
)

// CursorKey is the timeline state holding the highest device_seq uploaded.
const CursorKey = "upload_seq"

// Limits of one batch (edge-api/v1 EventsBatch).
const (
	MaxEvents = 500
	MaxGzip   = 1 << 20
	// maxBatches bounds one run, so a long offline backlog goes up over several runs.
	maxBatches = 20
)

var (
	// ErrRefused means the cloud no longer accepts this device (revoked or
	// its certificate expired); uploads stop until it enrolls again.
	ErrRefused = errors.New("the cloud refused this device's uploads")
	// ErrRetryLater means the cloud asked to slow down or is unavailable.
	ErrRetryLater = errors.New("the cloud is busy or unreachable; retrying later")
)

// Result is what one run sent.
type Result struct {
	Batches    int
	Accepted   int
	Duplicates int
	Rejected   int
	Remaining  int // events still to upload
	RetryAfter time.Duration
}

// Run uploads the events after the cursor, up to maxBatches batches. A
// rejected event is dropped and never retried, as the contract says.
func Run(ctx context.Context, base *http.Client, store *timeline.Store, env platform.Env, keys keystore.Store, privacy *bundles.BundlePrivacy) (*Result, error) {
	id, err := enroll.Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, bundles.ErrNotEnrolled
	}
	hashKey, _, err := enroll.HashKey(keys)
	if err != nil {
		return nil, err
	}
	client, err := enroll.MutualTLS(base, id, keys, 60*time.Second)
	if err != nil {
		return nil, err
	}
	cursor, err := Cursor(store)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	endpoint := strings.TrimSuffix(id.APIBaseURL, "/") + "/events:batch"
	for res.Batches < maxBatches {
		rows, err := store.Events(timeline.Query{AfterSeq: cursor, Limit: MaxEvents})
		if err != nil {
			return res, err
		}
		if len(rows) == 0 {
			break
		}
		evs := make([]events.Event, len(rows))
		for i, r := range rows {
			evs[i] = Prepare(r.Event, id, hashKey, privacy)
		}
		n, body, err := fit(evs)
		if err != nil {
			return res, err
		}
		out, retryAfter, err := send(ctx, client, endpoint, evs[:n], body)
		if err != nil {
			res.RetryAfter = retryAfter
			return res, err
		}
		res.Batches++
		res.Accepted += int(out.Accepted)
		res.Duplicates += int(out.Duplicates)
		res.Rejected += len(out.Rejected)
		cursor = evs[n-1].DeviceSeq
		if err := store.SetState(CursorKey, strconv.FormatInt(cursor, 10)); err != nil {
			return res, err
		}
	}
	b, err := store.BacklogAfter(cursor)
	if err != nil {
		return res, err
	}
	res.Remaining = b.Events
	return res, nil
}

// Cursor is the highest device_seq uploaded so far.
func Cursor(store *timeline.Store) (int64, error) {
	v, err := store.State(CursorKey)
	if err != nil || v == "" {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// Prepare turns a stored event into the one the cloud receives.
func Prepare(ev events.Event, id *enroll.Identity, hashKey []byte, privacy *bundles.BundlePrivacy) events.Event {
	ev.OrgID = id.OrgID
	ev.Device.DeviceID = id.DeviceID
	ev.User.UserID = id.UserID
	if ev.User.LocalUser != "" && !strings.HasPrefix(ev.User.LocalUser, "hmac-sha256:") {
		ev.User.LocalUser = redact.Hash(hashKey, ev.User.LocalUser)
	}
	red := map[string]contract.PrivacyLevel{}
	for k, v := range ev.Redaction {
		red[k] = v
	}
	red["user.local_user"] = contract.PrivacyLevelHashed
	ev.Redaction = red
	if privacy != nil {
		applyPrivacy(&ev, hashKey, privacy)
	}
	if cf := ev.ContentFinding; cf != nil {
		// Only a fingerprint under this organization's hash key can match the
		// same secret on other devices (PRD SCAN-15); one made before
		// enrollment, under the device's own salt, stays here.
		if key, _ := ev.Ext[FingerprintKeyExt].(string); cf.Fingerprint != "" && (key == "" || key != id.HashKeyID) {
			c := *cf
			c.Fingerprint = ""
			ev.ContentFinding = &c
		}
	}
	if _, ok := ev.Ext[FingerprintKeyExt]; ok {
		ext := map[string]any{}
		for k, v := range ev.Ext {
			if k != FingerprintKeyExt {
				ext[k] = v
			}
		}
		ev.Ext = ext
	}
	return ev
}

// FingerprintKeyExt is the local-only ext field naming the key of a content
// finding's fingerprint: the organization hash key's ID when enrolled.
const FingerprintKeyExt = "x_privometry_fingerprint_key"

// applyPrivacy applies the organization's upload levels to the fields this
// sensor stores, and omits the target of events in excluded repos.
func applyPrivacy(ev *events.Event, hashKey []byte, p *bundles.BundlePrivacy) {
	if ev.Action != nil {
		a := *ev.Action
		ev.Action = &a
	}
	if ev.Repo != nil {
		r := *ev.Repo
		ev.Repo = &r
	}
	excluded := false
	if ev.Repo != nil {
		for _, glob := range p.Exclusions {
			if ok, _ := path.Match(glob, ev.Repo.Remote); ok {
				excluded = true
			}
		}
	}
	if ev.Action != nil {
		level := p.UploadLevels["action.target"]
		if excluded {
			level = contract.PrivacyLevelOmitted
		}
		switch level {
		case contract.PrivacyLevelOmitted:
			ev.Action.Target = ""
			ev.Redaction["action.target"] = contract.PrivacyLevelOmitted
		case contract.PrivacyLevelHashed:
			if ev.Action.Target != "" {
				ev.Action.Target = redact.Hash(hashKey, ev.Action.Target)
				ev.Redaction["action.target"] = contract.PrivacyLevelHashed
			}
		}
	}
	if ev.Repo != nil {
		switch p.UploadLevels["repo.remote"] {
		case contract.PrivacyLevelOmitted:
			ev.Repo.Remote = ""
			ev.Redaction["repo.remote"] = contract.PrivacyLevelOmitted
		case contract.PrivacyLevelHashed:
			if ev.Repo.Remote != "" {
				ev.Repo.Remote = redact.Hash(hashKey, ev.Repo.Remote)
				ev.Redaction["repo.remote"] = contract.PrivacyLevelHashed
			}
		}
	}
}

// fit returns how many of evs fit in one batch and that batch, gzipped.
func fit(evs []events.Event) (int, []byte, error) {
	n := len(evs)
	for {
		raw, err := json.Marshal(cloud.EventsBatch{Events: evs[:n]})
		if err != nil {
			return 0, nil, err
		}
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(raw); err != nil {
			return 0, nil, err
		}
		if err := gz.Close(); err != nil {
			return 0, nil, err
		}
		if buf.Len() <= MaxGzip || n == 1 {
			return n, buf.Bytes(), nil
		}
		n /= 2
	}
}

func send(ctx context.Context, client *http.Client, endpoint string, batch []events.Event, body []byte) (*cloud.EventsBatchResult, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256([]byte(batch[0].EventID + batch[len(batch)-1].EventID + strconv.Itoa(len(batch))))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Idempotency-Key", base64.RawURLEncoding.EncodeToString(sum[:]))
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrRetryLater, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusOK:
		var out cloud.EventsBatchResult
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, 0, fmt.Errorf("upload: %w", err)
		}
		return &out, 0, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, 0, fmt.Errorf("%w: %d %s", ErrRefused, resp.StatusCode, problemTitle(raw))
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		after, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return nil, time.Duration(after) * time.Second, fmt.Errorf("%w: %d %s", ErrRetryLater, resp.StatusCode, problemTitle(raw))
	}
	return nil, 0, fmt.Errorf("upload: %s answered %d %s", endpoint, resp.StatusCode, problemTitle(raw))
}

func problemTitle(raw []byte) string {
	var p struct{ Title, Detail string }
	_ = json.Unmarshal(raw, &p)
	return strings.TrimSpace(p.Title + " " + p.Detail)
}
