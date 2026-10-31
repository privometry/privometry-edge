// Package approvals asks the organization for a remote approval of an ask
// (PRD CP-21; POST and GET /edge/v1/approvals) and waits for the answer. The
// daemon calls it in the background after it has already answered the hook
// (docs/spikes/remote-approvals.md).
package approvals

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/privometry/privometry-edge/internal/bundle"
	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/keystore"
	"github.com/privometry/privometry-edge/internal/platform"
)

// Client talks to the approvals endpoints as this device.
type Client struct {
	http *http.Client
	base string
}

// New returns a client for the enrolled device; base supplies the server roots.
func New(base *http.Client, env platform.Env) (*Client, error) {
	id, err := enroll.Load(env)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, bundle.ErrNotEnrolled
	}
	keys, err := keystore.Open(env, id.Keystore)
	if err != nil {
		return nil, err
	}
	c, err := enroll.MutualTLS(base, id, keys, 45*time.Second)
	if err != nil {
		return nil, err
	}
	return &Client{http: c, base: strings.TrimSuffix(id.APIBaseURL, "/")}, nil
}

// Create requests an approval.
func (c *Client) Create(ctx context.Context, req cloud.ApprovalCreate) (*cloud.Approval, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return c.do(ctx, http.MethodPost, c.base+"/approvals", body, http.StatusCreated)
}

// Wait long-polls an approval for up to wait (at most 30 seconds).
func (c *Client) Wait(ctx context.Context, id string, wait time.Duration) (*cloud.Approval, error) {
	secs := int(wait / time.Second)
	secs = max(0, min(secs, 30))
	return c.do(ctx, http.MethodGet, fmt.Sprintf("%s/approvals/%s?wait=%d", c.base, url.PathEscape(id), secs), nil, http.StatusOK)
}

func (c *Client) do(ctx context.Context, method, endpoint string, body []byte, want int) (*cloud.Approval, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		key := make([]byte, 16)
		_, _ = rand.Read(key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", hex.EncodeToString(key))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != want {
		var p struct{ Title, Detail string }
		_ = json.Unmarshal(raw, &p)
		return nil, fmt.Errorf("approvals: %s answered %d %s", endpoint, resp.StatusCode, strings.TrimSpace(p.Title+" "+p.Detail))
	}
	var out cloud.Approval
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	return &out, nil
}
