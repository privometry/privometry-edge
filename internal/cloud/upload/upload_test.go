package upload

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/enroll"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/redact"
)

func sample() events.Event {
	return events.Event{EventID: contract.NewID("evt"), DeviceSeq: 4, Device: events.Device{DeviceID: "dev_local"},
		User:      events.User{LocalUser: "meera"},
		Repo:      &events.Repo{Remote: "github.com/acme/payments"},
		Action:    &events.Action{Kind: contract.ActionKindShellExec, Target: "git push origin main"},
		Redaction: map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelRedacted}}
}

func TestPrepareForTheCloud(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	id := &enroll.Identity{OrgID: "org_01JA0000000000000000000001", DeviceID: "dev_01JA0000000000000000000002", UserID: "usr_01JA0000000000000000000003"}
	ev := sample()
	got := Prepare(ev, id, key, nil)
	if got.OrgID != id.OrgID || got.Device.DeviceID != id.DeviceID || got.User.UserID != id.UserID {
		t.Fatalf("identity: %+v", got)
	}
	if got.User.LocalUser != redact.Hash(key, "meera") || got.Redaction["user.local_user"] != contract.PrivacyLevelHashed {
		t.Fatalf("local user: %+v", got.User)
	}
	if again := Prepare(got, id, key, nil); again.User.LocalUser != got.User.LocalUser {
		t.Error("an already hashed user is not hashed twice")
	}
	if ev.Redaction["user.local_user"] != "" {
		t.Error("the stored event is not changed")
	}

	privacy := &bundles.BundlePrivacy{UploadLevels: map[string]contract.PrivacyLevel{"action.target": contract.PrivacyLevelHashed,
		"repo.remote": contract.PrivacyLevelOmitted}}
	p := Prepare(sample(), id, key, privacy)
	if p.Action.Target != redact.Hash(key, "git push origin main") || p.Repo.Remote != "" || p.Redaction["repo.remote"] != contract.PrivacyLevelOmitted {
		t.Fatalf("upload levels: %+v %+v %v", p.Action, p.Repo, p.Redaction)
	}
	excluded := Prepare(sample(), id, key, &bundles.BundlePrivacy{Exclusions: []string{"github.com/acme/*"}})
	if excluded.Action.Target != "" || excluded.Redaction["action.target"] != contract.PrivacyLevelOmitted {
		t.Fatalf("excluded repo: %+v", excluded.Action)
	}
}

func TestOnlyOrganizationFingerprintsLeave(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	id := &enroll.Identity{OrgID: "org_01JA0000000000000000000001", DeviceID: "dev_01JA0000000000000000000002", HashKeyID: "hk_01JA0000000000000000000009"}
	finding := func(keyID string) events.Event {
		ev := sample()
		ev.Type = events.EventTypeContentFinding
		ev.ContentFinding = &events.ContentFinding{Category: "credential", SecretType: "github_token", Fingerprint: "hmac-sha256:" + strings.Repeat("a", 64)}
		ev.Ext = map[string]any{"x_privometry_title": "GitHub token"}
		if keyID != "" {
			ev.Ext[FingerprintKeyExt] = keyID
		}
		return ev
	}
	org := finding(id.HashKeyID)
	if got := Prepare(org, id, key, nil); got.ContentFinding.Fingerprint == "" || got.Ext[FingerprintKeyExt] != nil || got.Ext["x_privometry_title"] == nil {
		t.Errorf("organization fingerprint: %+v %v", got.ContentFinding, got.Ext)
	}
	if org.Ext[FingerprintKeyExt] == nil {
		t.Error("the stored event is not changed")
	}
	for _, keyID := range []string{"", "hk_01JA00000000000000000000OLD"} {
		if got := Prepare(finding(keyID), id, key, nil); got.ContentFinding.Fingerprint != "" {
			t.Errorf("a fingerprint under %q left the device", keyID)
		}
	}
}

func TestBatchesFitInOneMegabyte(t *testing.T) {
	var evs []events.Event
	for range 400 {
		ev := sample()
		noise := make([]byte, 4096)
		_, _ = rand.Read(noise)
		ev.Action.Target = hex.EncodeToString(noise) // compresses to about half
		evs = append(evs, ev)
	}
	n, body, err := fit(evs)
	if err != nil || n >= len(evs) || len(body) > MaxGzip {
		t.Fatalf("fit: %d events, %d bytes, %v", n, len(body), err)
	}
}
