// Package extension is how a connector plugs into the edge. The daemon runs
// the connector a build registers, and the CLI adds its commands; with nothing
// registered the edge runs on its own, fully offline. A connector can never
// turn local protection off: it is told about the machine and may hand the
// edge signed data, but every decision stays local.
//
// pkg/edge re-exports this package for modules outside this repository.
package extension

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// Host is the daemon as a connector sees it.
type Host interface {
	// Timeline is the local event store, for uploads and heartbeats.
	Timeline() *timeline.Store
	SensorVersion() string
	AdapterSetVersion() int64
	// Hooks reports Privometry's hook in each supported agent.
	Hooks() []HookStatus
	// Scan runs a machine scan, without content detectors, for an inventory.
	Scan() (*scanner.Result, error)
	// Rescan rehashes agent configs and memory files in the background.
	Rescan()
	// SetFingerprintKey keys credential fingerprints with an organization's
	// hash key, so one leaked secret has one fingerprint on every device of
	// the organization; a nil key goes back to this device's own salt.
	SetFingerprintKey(key []byte, id string)
	// FingerprintKeyID is the ID of the key in use, or "" for the device salt.
	FingerprintKeyID() string
}

// HookState is how Privometry's hook stands in one agent.
type HookState string

// The states of a hook.
const (
	HookInstalled   HookState = "installed"
	HookModified    HookState = "modified" // partial, or pointing at another hook client
	HookDisabled    HookState = "disabled" // a user or managed setting turns the agent's hooks off
	HookMissing     HookState = "missing"
	HookUnsupported HookState = "unsupported"
)

// HookStatus is one agent's hook.
type HookStatus struct {
	Agent contract.AgentProduct
	Tier  contract.ConfigTier
	State HookState
}

// Connector links the device to a control plane. The daemon calls Sync every
// few seconds; the connector decides what is due.
type Connector interface {
	// Sync does the work due at now and reports whether the organization's
	// policy bundle changed.
	Sync(ctx context.Context, now time.Time) bool
	// UploadSoon asks the next Sync to send events whatever its schedule.
	UploadSoon()
}

// Approver is implemented by a connector that routes asks to people outside
// the agent, such as an organization's chat. The daemon keeps the approval's
// state; the approver only requests it and reports its outcome.
type Approver interface {
	RequestApproval(ctx context.Context, r ApprovalRequest) (Approval, error)
	// WaitApproval returns the approval once it changes, or after at most wait.
	WaitApproval(ctx context.Context, id string, wait time.Duration) (Approval, error)
}

// ApprovalRequest is one ask to approve. Target is always redacted.
type ApprovalRequest struct {
	EventID        string
	SessionID      string
	AgentProduct   contract.AgentProduct
	RepoRemote     string
	Kind           contract.ActionKind
	ToolName       string
	Target         string
	RuleIDs        []string
	Risk           contract.Risk
	Message        string
	TimeoutSeconds int64
}

// ApprovalStatus is where an approval stands.
type ApprovalStatus string

// The statuses of an approval.
const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalDenied   ApprovalStatus = "denied"
	ApprovalTimeout  ApprovalStatus = "timeout"
)

// Approval is a requested approval.
type Approval struct {
	ID     string
	Status ApprovalStatus
	// Responder is the display name of whoever decided, if known.
	Responder string
}

// Options are what the daemon gives a connector.
type Options struct {
	Env    platform.Env
	Logger *slog.Logger
}

// NewConnector makes a build's connector for one daemon.
type NewConnector func(Host, Options) (Connector, error)

// Command is a CLI command a connector adds to privometry.
type Command struct {
	Name    string
	Summary string // one line, for privometry's usage
	Run     func(args []string, stdout, stderr io.Writer) int
}

var (
	mu             sync.Mutex
	connector      NewConnector
	commands       []Command
	releaseChannel string
)

// SetReleaseChannel sets the release manifest privometry update installs
// from, so a connected build updates to the next connected build rather than
// the open-source one.
func SetReleaseChannel(manifestURL string) {
	mu.Lock()
	defer mu.Unlock()
	releaseChannel = manifestURL
}

// ReleaseChannel is the registered release manifest URL, or "".
func ReleaseChannel() string {
	mu.Lock()
	defer mu.Unlock()
	return releaseChannel
}

// SetConnector registers the build's connector. A build has at most one;
// setting another panics.
func SetConnector(f NewConnector) {
	mu.Lock()
	defer mu.Unlock()
	if connector != nil {
		panic("extension: a connector is already registered")
	}
	connector = f
}

// Registered is the build's connector, or nil.
func Registered() NewConnector {
	mu.Lock()
	defer mu.Unlock()
	return connector
}

// AddCommand adds a CLI command. Adding a name twice panics.
func AddCommand(c Command) {
	mu.Lock()
	defer mu.Unlock()
	if slices.ContainsFunc(commands, func(o Command) bool { return o.Name == c.Name }) {
		panic("extension: command " + c.Name + " is already registered")
	}
	commands = append(commands, c)
}

// Commands are the added CLI commands, in the order they were added.
func Commands() []Command {
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(commands)
}
