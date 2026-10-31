// Package edge is the public way to build on privometry-edge: a connected
// build registers a connector and its CLI commands, then runs the edge's own
// binaries. It is the only package outside this repository may import; what
// it exposes is what a connector needs and nothing more.
//
//	func main() {
//		edge.SetConnector(myconnector.New)
//		os.Exit(edge.RunDaemon(os.Args[1:]))
//	}
//
// Without a connector the edge runs on its own and never contacts a control
// plane. See internal/extension for the contract.
package edge

import (
	"io"

	"github.com/privometry/privometry-edge/internal/cli"
	"github.com/privometry/privometry-edge/internal/contract"
	"github.com/privometry/privometry-edge/internal/daemoncmd"
	"github.com/privometry/privometry-edge/internal/extension"
	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/scanner"
	"github.com/privometry/privometry-edge/internal/timeline"
)

// The connector contract (internal/extension).
type (
	// Host is the daemon as a connector sees it.
	Host = extension.Host
	// Connector links the device to a control plane.
	Connector = extension.Connector
	// NewConnector makes a build's connector for one daemon.
	NewConnector = extension.NewConnector
	// Options are what the daemon gives a connector.
	Options = extension.Options
	// Approver routes asks to people outside the agent.
	Approver = extension.Approver
	// ApprovalRequest is one ask to approve.
	ApprovalRequest = extension.ApprovalRequest
	// Approval is a requested approval.
	Approval = extension.Approval
	// ApprovalStatus is where an approval stands.
	ApprovalStatus = extension.ApprovalStatus
	// HookStatus is one agent's hook.
	HookStatus = extension.HookStatus
	// HookState is how Privometry's hook stands in one agent.
	HookState = extension.HookState
	// Command is a CLI command a connector adds to privometry.
	Command = extension.Command
)

// Hook states and approval statuses.
const (
	HookInstalled   = extension.HookInstalled
	HookModified    = extension.HookModified
	HookDisabled    = extension.HookDisabled
	HookMissing     = extension.HookMissing
	HookUnsupported = extension.HookUnsupported

	ApprovalPending  = extension.ApprovalPending
	ApprovalApproved = extension.ApprovalApproved
	ApprovalDenied   = extension.ApprovalDenied
	ApprovalTimeout  = extension.ApprovalTimeout
)

// Types the contract refers to.
type (
	// Env is the platform: OS, home and data directories.
	Env = platform.Env
	// Timeline is the local event store.
	Timeline = timeline.Store
	// ScanResult is a machine scan.
	ScanResult = scanner.Result
	// AgentProduct names a coding agent.
	AgentProduct = contract.AgentProduct
	// ConfigTier is a config tier: user, project or managed.
	ConfigTier = contract.ConfigTier
	// ActionKind is the kind of an agent action.
	ActionKind = contract.ActionKind
	// Risk is a risk level.
	Risk = contract.Risk
)

// SetConnector registers the build's connector; call it before RunDaemon or
// RunCLI. A build has at most one.
func SetConnector(f NewConnector) { extension.SetConnector(f) }

// AddCommand adds a command to privometry; call it before RunCLI.
func AddCommand(c Command) { extension.AddCommand(c) }

// RunCLI runs privometry with args (without the program name) and returns its
// exit code.
func RunCLI(args []string, stdout, stderr io.Writer) int { return cli.Run(args, stdout, stderr) }

// RunDaemon runs privometryd with args (without the program name) and returns
// its exit code.
func RunDaemon(args []string) int { return daemoncmd.Main(args) }
