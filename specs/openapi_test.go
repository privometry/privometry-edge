package specs_test

import (
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/privometry/privometry-edge/specs"
)

// TestEdgeAPI checks openapi.yaml against the edge API contract. It is not a
// full OpenAPI validator; CI should also run an OpenAPI 3.1 linter.
func TestEdgeAPI(t *testing.T) {
	// The nine endpoints of Contracts v1 (approvals has two operations).
	checkAPI(t, "edge-api/v1", []string{
		"GET /adapters", "GET /approvals/{approval_id}", "GET /bundle", "GET /riskfeed",
		"POST /approvals", "POST /certs:renew", "POST /enroll", "POST /events:batch",
		"POST /heartbeat", "POST /inventory",
	}, func(method string, _ map[string]any) bool { return method == "post" })
}

// TestAccountAPI checks the account API the same way. Registration and
// sign-in POSTs are public and take no Idempotency-Key, since each code,
// challenge and link works once; POSTs made with a session take one. The
// global tier's operations name their own server.
func TestAccountAPI(t *testing.T) {
	doc := checkAPI(t, "account-api/v1", []string{
		"DELETE /me/credentials/{credential_id}", "DELETE /orgs/{org_id}/api-keys/{api_key_id}", "DELETE /orgs/{org_id}/devices/{device_id}",
		"DELETE /orgs/{org_id}/enrollment-tokens/{enrollment_token_id}", "GET /directory/{slug}", "GET /me",
		"GET /me/credentials", "GET /orgs/{org_id}/api-keys", "GET /orgs/{org_id}/devices", "GET /orgs/{org_id}/enrollment-tokens",
		"GET /orgs/{org_id}/members", "GET /regions", "POST /orgs/{org_id}/api-keys", "POST /orgs/{org_id}/enrollment-tokens",
		"POST /orgs/{org_id}/invitations", "POST /orgs/{org_id}/members/{user_id}:reset",
		"POST /registrations", "POST /registrations/{registration_id}:complete",
		"POST /registrations/{registration_id}:resend", "POST /registrations/{registration_id}:verify",
		"POST /sign-in", "POST /sign-in/challenges", "POST /sign-in/links:redeem", "POST /sign-out",
	}, func(method string, op map[string]any) bool { return method == "post" && !public(op) })
	for _, p := range []string{"/regions", "/directory/{slug}"} {
		servers, _ := lookup(doc, "#/paths/"+strings.ReplaceAll(p, "/", "~1")+"/servers").([]any)
		if len(servers) != 1 || !strings.HasPrefix(servers[0].(map[string]any)["url"].(string), "https://api.") {
			t.Errorf("%s must be served by the global tier", p)
		}
	}
}

// TestOrgAPI checks the organization API. Every POST that changes state
// takes an Idempotency-Key; :check only compiles.
func TestOrgAPI(t *testing.T) {
	checkAPI(t, "org-api/v1", []string{
		"DELETE /orgs/{org_id}/catalog/{catalog_entry_id}", "DELETE /orgs/{org_id}/integrations/{integration_id}",
		"DELETE /orgs/{org_id}/policies/{policy_id}", "DELETE /orgs/{org_id}/webhooks/{webhook_id}", "GET /orgs/{org_id}/approval-settings",
		"GET /orgs/{org_id}/approvals", "GET /orgs/{org_id}/billing/invoices", "GET /orgs/{org_id}/bundles", "GET /orgs/{org_id}/catalog",
		"GET /orgs/{org_id}/credentials", "GET /orgs/{org_id}/credentials/{credential_id}",
		"GET /orgs/{org_id}/events", "GET /orgs/{org_id}/findings", "GET /orgs/{org_id}/integrations", "GET /orgs/{org_id}/inventory/agents",
		"GET /orgs/{org_id}/inventory/components", "GET /orgs/{org_id}/license", "GET /orgs/{org_id}/license/events", "GET /orgs/{org_id}/overview",
		"GET /orgs/{org_id}/policies", "GET /orgs/{org_id}/policies/{policy_id}", "GET /orgs/{org_id}/policies/{policy_id}/diff",
		"GET /orgs/{org_id}/policies/{policy_id}/versions", "GET /orgs/{org_id}/policies/{policy_id}/versions/{version}",
		"GET /orgs/{org_id}/webhooks", "GET /orgs/{org_id}/webhooks/{webhook_id}/deliveries", "POST /orgs/{org_id}/approvals/{approval_id}:decide",
		"POST /orgs/{org_id}/billing/invoices/{invoice_id}:download", "POST /orgs/{org_id}/billing:cancel", "POST /orgs/{org_id}/billing:checkout",
		"POST /orgs/{org_id}/billing:seats", "POST /orgs/{org_id}/bundles", "POST /orgs/{org_id}/catalog",
		"POST /orgs/{org_id}/credentials/{credential_id}:mark",
		"POST /orgs/{org_id}/findings/{finding_id}:triage", "POST /orgs/{org_id}/integrations", "POST /orgs/{org_id}/policies",
		"POST /orgs/{org_id}/policies/{policy_id}/versions", "POST /orgs/{org_id}/policies/{policy_id}:rollback",
		"POST /orgs/{org_id}/policies:check", "POST /orgs/{org_id}/webhooks", "POST /orgs/{org_id}/webhooks/{webhook_id}:rotate-secret", "POST /orgs/{org_id}/webhooks/{webhook_id}:test",
		"PUT /orgs/{org_id}/approval-settings", "PUT /orgs/{org_id}/webhooks/{webhook_id}",
	}, func(method string, op map[string]any) bool {
		return method == "post" && op["operationId"] != "checkPolicy"
	})
}

// checkAPI checks the rules every Privometry API follows and returns the
// parsed document. keyed reports whether an operation must accept
// Idempotency-Key; otherwise it must not.
func checkAPI(t *testing.T, dir string, want []string, keyed func(method string, op map[string]any) bool) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(dir + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Fatalf("openapi version %q, want 3.1.x", v)
	}

	var got []string
	ids := map[string]bool{}
	paths := doc["paths"].(map[string]any)
	for p, item := range paths {
		for method, op := range item.(map[string]any) {
			if !slices.Contains([]string{"get", "put", "post", "delete", "patch"}, method) {
				continue // servers, parameters, summary
			}
			op := op.(map[string]any)
			name := strings.ToUpper(method) + " " + p
			got = append(got, name)
			id, _ := op["operationId"].(string)
			if id == "" || ids[id] {
				t.Errorf("%s: missing or duplicate operationId %q", name, id)
			}
			ids[id] = true
			switch has := hasParam(op, "#/components/parameters/IdempotencyKey"); {
			case keyed(method, op) && !has:
				t.Errorf("%s: must accept Idempotency-Key", name)
			case !keyed(method, op) && has:
				t.Errorf("%s: must not take Idempotency-Key", name)
			}
			responses := op["responses"].(map[string]any)
			if _, ok := responses["429"]; !ok {
				t.Errorf("%s: must document 429", name)
			}
			for code, r := range responses {
				if (code[0] == '4' || code[0] == '5') && !isProblem(doc, r) {
					t.Errorf("%s %s: error responses must be application/problem+json", name, code)
				}
			}
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, want) {
		t.Errorf("operations:\n got %v\nwant %v", got, want)
	}
	if tm := lookup(doc, "#/components/responses/TooManyRequests/headers/Retry-After"); tm == nil {
		t.Error("429 responses must carry Retry-After")
	}

	// Every $ref resolves: local refs inside the document, file refs compile.
	walkRefs(doc, func(ref string) {
		if strings.HasPrefix(ref, "#") {
			if lookup(doc, ref) == nil {
				t.Errorf("unresolved local $ref %s", ref)
			}
			return
		}
		file, frag, _ := strings.Cut(ref, "#")
		target := path.Clean(path.Join(dir, file))
		if frag != "" {
			target += "#" + frag
		}
		if _, err := specs.Schema(target); err != nil {
			t.Errorf("$ref %s: %v", ref, err)
		}
	})
	return doc
}

// public reports whether an operation needs no authentication.
func public(op map[string]any) bool {
	sec, ok := op["security"].([]any)
	if !ok || len(sec) != 1 {
		return false
	}
	m, _ := sec[0].(map[string]any)
	return len(m) == 0
}

func hasParam(op map[string]any, ref string) bool {
	params, _ := op["parameters"].([]any)
	for _, p := range params {
		if m, ok := p.(map[string]any); ok && m["$ref"] == ref {
			return true
		}
	}
	return false
}

func isProblem(doc map[string]any, r any) bool {
	m, _ := r.(map[string]any)
	if ref, ok := m["$ref"].(string); ok {
		m, _ = lookup(doc, ref).(map[string]any)
	}
	content, _ := m["content"].(map[string]any)
	_, ok := content["application/problem+json"]
	return ok
}

func lookup(doc map[string]any, ref string) any {
	var cur any = doc
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		part = strings.NewReplacer("~1", "/", "~0", "~").Replace(part)
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

func walkRefs(v any, fn func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && k == "$ref" {
				fn(s)
				continue
			}
			walkRefs(e, fn)
		}
	case []any:
		for _, e := range x {
			walkRefs(e, fn)
		}
	}
}
