package account

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	cloudaccount "github.com/privometry/privometry-oss/internal/cloud/account"
)

// DefaultAPI is the account API of the India region, where organizations live
// at launch. The host is a placeholder until it is registered.
const DefaultAPI = "https://in.api.privometry.dev/account/v1"

const maxResponse = 1 << 20

// Problem is an RFC 9457 problem the account API answered with.
type Problem struct {
	Status           int    `json:"status"`
	Type             string `json:"type"`
	Title            string `json:"title"`
	Detail           string `json:"detail"`
	CodeAttemptsLeft *int   `json:"code_attempts_left"`
	RetryAfter       string `json:"-"`
}

func (p *Problem) Error() string {
	msg := p.Title
	if p.Detail != "" {
		msg += ": " + p.Detail
	}
	return msg
}

// Kind is the problem type's last segment, such as invalid-code.
func (p *Problem) Kind() string {
	return p.Type[strings.LastIndex(p.Type, "/")+1:]
}

// IsProblem reports whether err is a problem of the given kind.
func IsProblem(err error, kind string) bool {
	var p *Problem
	return errors.As(err, &p) && p.Kind() == kind
}

// Client calls the account API of one region.
type Client struct {
	BaseURL   string // for example https://in.api.privometry.dev/account/v1
	HTTP      *http.Client
	UserAgent string
}

func (c *Client) StartRegistration(ctx context.Context, r cloudaccount.RegistrationStart) (*cloudaccount.Registration, error) {
	var out cloudaccount.Registration
	return &out, c.post(ctx, "/registrations", r, http.StatusAccepted, &out)
}

func (c *Client) ResendCode(ctx context.Context, registrationID string) (*cloudaccount.Registration, error) {
	var out cloudaccount.Registration
	return &out, c.post(ctx, "/registrations/"+url.PathEscape(registrationID)+":resend", nil, http.StatusAccepted, &out)
}

func (c *Client) VerifyCode(ctx context.Context, registrationID, code string) (*cloudaccount.RegistrationChallenge, error) {
	var out cloudaccount.RegistrationChallenge
	return &out, c.post(ctx, "/registrations/"+url.PathEscape(registrationID)+":verify", cloudaccount.RegistrationVerify{Code: code},
		http.StatusOK, &out)
}

func (c *Client) CompleteRegistration(ctx context.Context, registrationID string, r cloudaccount.RegistrationComplete) (*cloudaccount.RegistrationResult, error) {
	var out cloudaccount.RegistrationResult
	return &out, c.post(ctx, "/registrations/"+url.PathEscape(registrationID)+":complete", r, http.StatusCreated, &out)
}

func (c *Client) SignInChallenge(ctx context.Context, credentialID string) (*cloudaccount.SignInChallenge, error) {
	var out cloudaccount.SignInChallenge
	req := cloudaccount.SignInChallengeRequest{Method: cloudaccount.CredentialTypeCLIKey, CredentialID: credentialID}
	return &out, c.post(ctx, "/sign-in/challenges", req, http.StatusCreated, &out)
}

func (c *Client) SignIn(ctx context.Context, r cloudaccount.SignInRequest) (*cloudaccount.SignInResult, error) {
	var out cloudaccount.SignInResult
	return &out, c.post(ctx, "/sign-in", r, http.StatusOK, &out)
}

func (c *Client) post(ctx context.Context, path string, body any, want int, out any) error {
	base, err := url.Parse(c.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return fmt.Errorf("account: %q is not an HTTPS URL", c.BaseURL)
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.BaseURL, "/")+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // never follow
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}
	if resp.StatusCode != want {
		p := &Problem{Status: resp.StatusCode, Title: resp.Status, RetryAfter: resp.Header.Get("Retry-After")}
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
			_ = json.Unmarshal(raw, p)
		}
		if p.Type == "" {
			p.Type = "about:blank"
		}
		return p
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("account: %s answered %w", path, err)
	}
	return nil
}
