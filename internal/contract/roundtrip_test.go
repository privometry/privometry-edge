package contract_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/privometry/privometry-edge/internal/adapters/registry"
	"github.com/privometry/privometry-edge/internal/cloud"
	"github.com/privometry/privometry-edge/internal/cloud/account"
	"github.com/privometry/privometry-edge/internal/cloud/bundles"
	"github.com/privometry/privometry-edge/internal/cloud/entitlements"
	"github.com/privometry/privometry-edge/internal/cloud/orgapi"
	"github.com/privometry/privometry-edge/internal/content"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/events"
	"github.com/privometry/privometry-edge/internal/policy/rulepack"
	"github.com/privometry/privometry-edge/internal/riskfeed"
	"github.com/privometry/privometry-edge/internal/update"
	"github.com/privometry/privometry-edge/specs"
)

const root = "../.."

type target struct {
	glob   string     // files under the repo root
	schema string     // schema path under specs/
	new    func() any // returns a pointer to the generated type
}

var targets = []target{
	{"specs/common/v1/examples/dsse/valid/*", "common/v1/dsse.schema.json", func() any { return new(contract.Envelope) }},
	{"specs/common/v1/examples/keyset/valid/*", "common/v1/keyset.schema.json", func() any { return new(contract.KeySet) }},
	{"specs/conformance/signatures/*.json", "common/v1/keyset.schema.json", func() any { return new(contract.KeySet) }},
	{"specs/event-schema/v1/examples/valid/*", "event-schema/v1/event.schema.json", func() any { return new(events.Event) }},
	{"specs/adapter/v1/examples/valid/*", "adapter/v1/adapter.schema.json", func() any { return new(registry.Adapter) }},
	{"specs/adapter/v1/examples/adapter-set/valid/*", "adapter/v1/adapter-set.schema.json", func() any { return new(registry.AdapterSet) }},
	{"specs/policy/v1/examples/bundle/valid/*", "policy/v1/bundle.schema.json", func() any { return new(bundles.Bundle) }},
	{"specs/entitlements/v1/examples/entitlements/valid/*", "entitlements/v1/entitlements.schema.json", func() any { return new(entitlements.Entitlements) }},
	{"specs/entitlements/v1/examples/license/valid/*", "entitlements/v1/license.schema.json", func() any { return new(entitlements.License) }},
	{"specs/entitlements/v1/feature-registry.json", "entitlements/v1/feature-registry.schema.json", func() any { return new(entitlements.FeatureRegistry) }},
	{"specs/riskfeed/v1/examples/valid/*", "riskfeed/v1/riskfeed.schema.json", func() any { return new(riskfeed.Document) }},
	{"specs/release/v1/examples/valid/*", "release/v1/release.schema.json", func() any { return new(update.Release) }},
	{"specs/detectorpack/v1/examples/pack/valid/*", "detectorpack/v1/pack.schema.json", func() any { return new(content.Manifest) }},
	{"specs/detectorpack/v1/examples/detectors/valid/*", "detectorpack/v1/detectors.schema.json", func() any { return new(content.DetectorsFile) }},
	{"specs/detectorpack/v1/examples/pack-set/valid/*", "detectorpack/v1/pack-set.schema.json", func() any { return new(content.PackSet) }},
	{"specs/rulepack/v1/examples/pack/valid/*", "rulepack/v1/pack.schema.json", func() any { return new(rulepack.Manifest) }},
	{"specs/rulepack/v1/examples/ruletest/valid/*", "rulepack/v1/ruletest.schema.json", func() any { return new(rulepack.TestFile) }},
	{"rulepacks/*/pack.yaml", "rulepack/v1/pack.schema.json", func() any { return new(rulepack.Manifest) }},
	{"rulepacks/*/tests/*.test.yaml", "rulepack/v1/ruletest.schema.json", func() any { return new(rulepack.TestFile) }},
}

// messages maps each edge API example folder to its generated type.
var messages = map[string]func() any{
	"EnrollRequest": func() any { return new(cloud.EnrollRequest) }, "EnrollResponse": func() any { return new(cloud.EnrollResponse) },
	"RenewRequest": func() any { return new(cloud.RenewRequest) }, "RenewResponse": func() any { return new(cloud.RenewResponse) },
	"EventsBatch": func() any { return new(cloud.EventsBatch) }, "EventsBatchResult": func() any { return new(cloud.EventsBatchResult) },
	"InventorySnapshot": func() any { return new(cloud.InventorySnapshot) }, "InventoryReceipt": func() any { return new(cloud.InventoryReceipt) },
	"Heartbeat": func() any { return new(cloud.Heartbeat) }, "HeartbeatResponse": func() any { return new(cloud.HeartbeatResponse) },
	"Command": func() any { return new(cloud.Command) }, "ApprovalCreate": func() any { return new(cloud.ApprovalCreate) },
	"Approval": func() any { return new(cloud.Approval) }, "Problem": func() any { return new(cloud.Problem) },
}

// accountMessages maps each account API example folder to its generated type.
var accountMessages = map[string]func() any{
	"RegionList": func() any { return new(account.RegionList) }, "OrgLocation": func() any { return new(account.OrgLocation) },
	"RegistrationStart": func() any { return new(account.RegistrationStart) }, "Registration": func() any { return new(account.Registration) },
	"RegistrationVerify":    func() any { return new(account.RegistrationVerify) },
	"RegistrationChallenge": func() any { return new(account.RegistrationChallenge) },
	"RegistrationComplete":  func() any { return new(account.RegistrationComplete) },
	"RegistrationResult":    func() any { return new(account.RegistrationResult) },
	"AccountProof":          func() any { return new(account.AccountProof) }, "Proof": func() any { return new(account.Proof) },
	"SignInChallengeRequest": func() any { return new(account.SignInChallengeRequest) },
	"SignInChallenge":        func() any { return new(account.SignInChallenge) },
	"SignInRequest":          func() any { return new(account.SignInRequest) }, "SignInResult": func() any { return new(account.SignInResult) },
	"SignInLinkRedeem": func() any { return new(account.SignInLinkRedeem) }, "Me": func() any { return new(account.Me) },
	"CredentialList": func() any { return new(account.CredentialList) }, "InvitationCreate": func() any { return new(account.InvitationCreate) },
	"Invitation":             func() any { return new(account.Invitation) },
	"MemberResetRequest":     func() any { return new(account.MemberResetRequest) },
	"MemberResetResult":      func() any { return new(account.MemberResetResult) },
	"MemberList":             func() any { return new(account.MemberList) },
	"ApiKeyCreate":           func() any { return new(account.APIKeyCreate) },
	"ApiKey":                 func() any { return new(account.APIKey) },
	"ApiKeyCreated":          func() any { return new(account.APIKeyCreated) },
	"ApiKeyList":             func() any { return new(account.APIKeyList) },
	"EnrollmentTokenCreate":  func() any { return new(account.EnrollmentTokenCreate) },
	"EnrollmentToken":        func() any { return new(account.EnrollmentToken) },
	"EnrollmentTokenCreated": func() any { return new(account.EnrollmentTokenCreated) },
	"EnrollmentTokenList":    func() any { return new(account.EnrollmentTokenList) },
	"DeviceList":             func() any { return new(account.DeviceList) },
}

// orgMessages maps each organization API example folder to its generated type.
var orgMessages = map[string]func() any{
	"PolicyCreate": func() any { return new(orgapi.PolicyCreate) }, "PolicyVersionCreate": func() any { return new(orgapi.PolicyVersionCreate) },
	"PolicyRollback": func() any { return new(orgapi.PolicyRollback) }, "PolicyCheck": func() any { return new(orgapi.PolicyCheck) },
	"PolicyCheckResult": func() any { return new(orgapi.PolicyCheckResult) }, "Policy": func() any { return new(orgapi.Policy) },
	"PolicyList": func() any { return new(orgapi.PolicyList) }, "PolicyVersion": func() any { return new(orgapi.PolicyVersion) },
	"PolicyVersionList": func() any { return new(orgapi.PolicyVersionList) }, "PolicyDiff": func() any { return new(orgapi.PolicyDiff) },
	"BundlePublish": func() any { return new(orgapi.BundlePublish) }, "BundleInfo": func() any { return new(orgapi.BundleInfo) },
	"BundleList": func() any { return new(orgapi.BundleList) }, "EventPage": func() any { return new(orgapi.EventPage) },
	"CatalogEntryCreate": func() any { return new(orgapi.CatalogEntryCreate) }, "CatalogEntry": func() any { return new(orgapi.CatalogEntry) },
	"CatalogEntryList": func() any { return new(orgapi.CatalogEntryList) }, "ComponentList": func() any { return new(orgapi.ComponentList) },
	"AgentInstanceList": func() any { return new(orgapi.AgentInstanceList) },
	"FindingList":       func() any { return new(orgapi.FindingList) }, "FindingTriage": func() any { return new(orgapi.FindingTriage) },
	"IntegrationCreate": func() any { return new(orgapi.IntegrationCreate) }, "IntegrationCreated": func() any { return new(orgapi.IntegrationCreated) },
	"IntegrationList":  func() any { return new(orgapi.IntegrationList) },
	"ApprovalSettings": func() any { return new(orgapi.ApprovalSettings) }, "ApprovalList": func() any { return new(orgapi.ApprovalList) },
	"ApprovalDecision":       func() any { return new(orgapi.ApprovalDecision) },
	"WebhookCreate":          func() any { return new(orgapi.WebhookCreate) },
	"WebhookUpdate":          func() any { return new(orgapi.WebhookUpdate) },
	"WebhookSecretRotate":    func() any { return new(orgapi.WebhookSecretRotate) },
	"WebhookCreated":         func() any { return new(orgapi.WebhookCreated) },
	"WebhookList":            func() any { return new(orgapi.WebhookList) },
	"WebhookDelivery":        func() any { return new(orgapi.WebhookDelivery) },
	"WebhookDeliveryList":    func() any { return new(orgapi.WebhookDeliveryList) },
	"WebhookEvent":           func() any { return new(orgapi.WebhookEvent) },
	"OrgOverview":            func() any { return new(orgapi.OrgOverview) },
	"License":                func() any { return new(orgapi.License) },
	"LicenseEventList":       func() any { return new(orgapi.LicenseEventList) },
	"BillingCheckout":        func() any { return new(orgapi.BillingCheckout) },
	"BillingCheckoutStarted": func() any { return new(orgapi.BillingCheckoutStarted) },
	"BillingSeats":           func() any { return new(orgapi.BillingSeats) },
	"InvoiceList":            func() any { return new(orgapi.InvoiceList) },
	"InvoiceDownload":        func() any { return new(orgapi.InvoiceDownload) },
	"CredentialList":         func() any { return new(orgapi.CredentialList) },
	"CredentialDetail":       func() any { return new(orgapi.CredentialDetail) },
	"CredentialMark":         func() any { return new(orgapi.CredentialMark) },
}

// TestRoundTrip decodes every valid example strictly into its generated type,
// encodes it again, and requires the same document, still valid.
func TestRoundTrip(t *testing.T) {
	all := targets
	for api, types := range map[string]map[string]func() any{"edge-api/v1": messages, "account-api/v1": accountMessages, "org-api/v1": orgMessages} {
		for name, fn := range types {
			all = append(all, target{"specs/" + api + "/examples/" + name + "/valid/*", api + "/messages.schema.json#/$defs/" + name, fn})
		}
		dirs, _ := filepath.Glob(filepath.Join(root, "specs", api, "examples/*"))
		if len(dirs) != len(types) {
			t.Errorf("%s: %d message example folders, %d mapped types", api, len(dirs), len(types))
		}
	}
	for _, tg := range all {
		files, _ := filepath.Glob(filepath.Join(root, tg.glob))
		if len(files) == 0 {
			t.Errorf("no files for %s", tg.glob)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "vectors.json") {
				continue
			}
			t.Run(strings.TrimPrefix(f, root+"/"), func(t *testing.T) { roundTrip(t, f, tg) })
		}
	}
}

func roundTrip(t *testing.T, file string, tg target) {
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := specs.Decode(file, raw) // YAML becomes JSON-compatible values
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(inst)
	if err != nil {
		t.Fatal(err)
	}
	v := tg.new()
	dec := json.NewDecoder(bytes.NewReader(original))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode into %T: %v", v, err)
	}
	again, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := specs.Validate(tg.schema, "roundtrip.json", again); err != nil {
		t.Errorf("re-encoded document is invalid: %v", err)
	}
	if a, b := normalize(t, original), normalize(t, again); !reflect.DeepEqual(a, b) {
		t.Errorf("round trip changed the document\n before %s\n after  %s", original, again)
	}
}

// normalize decodes JSON and drops null members and empty arrays: for an
// optional field, absent, null and [] mean the same thing in every contract.
// Required fields are covered by re-validating the encoded document.
func normalize(t *testing.T, raw []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return dropNulls(v)
}

func dropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if a, ok := e.([]any); e == nil || ok && len(a) == 0 {
				delete(x, k)
				continue
			}
			x[k] = dropNulls(e)
		}
	case []any:
		for i, e := range x {
			x[i] = dropNulls(e)
		}
	}
	return v
}
