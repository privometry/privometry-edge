package contract_test

import (
	"reflect"
	"testing"

	"github.com/privometry/privometry-oss/internal/contract"
)

func TestDefaultFailModes(t *testing.T) {
	want := map[string]contract.FailMode{
		"catastrophic":   contract.FailModeClosed,
		"secrets":        contract.FailModeAsk,
		"exfiltration":   contract.FailModeAsk,
		"unapproved_mcp": contract.FailModeOpen,
		"other":          contract.FailModeOpen,
	}
	got := contract.DefaultFailModes()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultFailModes() = %#v, want %#v", got, want)
	}

	got["catastrophic"] = contract.FailModeOpen
	if next := contract.DefaultFailModes()["catastrophic"]; next != contract.FailModeClosed {
		t.Fatalf("caller mutation changed defaults to %q", next)
	}
}
