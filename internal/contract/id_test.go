package contract_test

import (
	"regexp"
	"testing"
	"time"

	"github.com/privometry/privometry-oss/internal/contract"
)

func TestNewID(t *testing.T) {
	re := regexp.MustCompile(`^evt_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	seen := map[string]bool{}
	for range 1000 {
		id := contract.NewID("evt")
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("bad or duplicate id %q", id)
		}
		seen[id] = true
	}
	a := contract.ULID(time.UnixMilli(1_700_000_000_000))
	b := contract.ULID(time.UnixMilli(1_700_000_000_001))
	if a[:10] >= b[:10] {
		t.Errorf("time prefix must sort: %s %s", a, b)
	}
	if got := contract.ULID(time.UnixMilli(0))[:10]; got != "0000000000" {
		t.Errorf("epoch prefix %s", got)
	}
}
