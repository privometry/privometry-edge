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

// The connector contract.
type (
	Host            = extension.Host
	Connector       = extension.Connector
	NewConnector    = extension.NewConnector
	Options         = extension.Options
	Approver        = extension.Approver
	ApprovalRequest = extension.ApprovalRequest
	Approval        = extension.Approval
	ApprovalStatus  = extension.ApprovalStatus
	HookStatus      = extension.HookStatus
	HookState       = extension.HookState
	Command         = extension.Command
)

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
	Env          = platform.Env
	Timeline     = timeline.Store
	ScanResult   = scanner.Result
	AgentProduct = contract.AgentProduct
	ConfigTier   = contract.ConfigTier
	ActionKind   = contract.ActionKind
	Risk         = contract.Risk
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
