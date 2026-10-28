package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/privometry/privometry-oss/internal/adapters/registry"
	"github.com/privometry/privometry-oss/internal/contract"
	"github.com/privometry/privometry-oss/internal/guard"
	"github.com/privometry/privometry-oss/internal/scanner/discover"
)

const mcpUsage = `Usage: privometry mcp <status|wrap|unwrap> [flags]

Run local stdio MCP servers through privometry-mcp-shim, which checks each tool
call with Privometry before the server sees it and scans the tool descriptions
servers give the model. Only your user-level MCP configs are edited; remote
(http) servers and repo configs are left alone.

When an agent's own Privometry hook is active, the hook decides its MCP calls
and the shim only scans tool descriptions and reports servers whose tools
change. Restart the agent after wrapping so it starts the shim.

  privometry mcp status            list MCP servers and whether each is wrapped
  privometry mcp wrap [--dry-run]  wrap each local stdio server
  privometry mcp unwrap            restore each server's own command

Flags:
`

func mcpCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, mcpUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("mcp "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, mcpUsage); fs.PrintDefaults() }
	agentFlag := fs.String("agent", "", "only this agent, for example codex_cli (default: every agent)")
	dryRun := fs.Bool("dry-run", false, "show the change without writing it")
	shimPath := fs.String("shim", "", "path of privometry-mcp-shim (default: next to this privometry binary)")
	format := fs.String("format", "table", "status output: table or json")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if sub != "status" && sub != "wrap" && sub != "unwrap" {
		fmt.Fprint(stderr, mcpUsage)
		return 2
	}
	env, err := guardEnv()
	if err != nil {
		return fail(stderr, err)
	}
	reg, err := loadAdapters(env)
	if err != nil {
		return fail(stderr, err)
	}
	var agents []registry.Adapter
	for _, a := range reg.All() {
		if *agentFlag == "" || string(a.Agent) == *agentFlag {
			agents = append(agents, a)
		}
	}
	if len(agents) == 0 {
		return fail(stderr, fmt.Errorf("unknown agent %q", *agentFlag))
	}
	opts := guard.Options{Env: env}

	if sub == "status" {
		var all []guard.MCPServer
		for _, a := range agents {
			servers, err := guard.MCPServers(a, opts)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", a.DisplayName, err)
			}
			all = append(all, servers...)
		}
		return mcpStatus(all, *format, env.Home, reg, stdout)
	}

	shim := ""
	if sub == "wrap" {
		if shim, err = sibling(*shimPath, guard.ShimName); err != nil {
			return fail(stderr, fmt.Errorf("%w (use --shim)", err))
		}
	}
	code, changed := 0, 0
	for _, a := range agents {
		var changes []*guard.Change
		if sub == "wrap" {
			changes, err = guard.WrapMCP(a, opts, shim)
		} else {
			changes, err = guard.UnwrapMCP(a, opts)
		}
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", a.DisplayName, err)
			code = 1
			continue
		}
		for _, c := range changes {
			path := discover.Display(c.Path, env.Home, "")
			if *dryRun {
				fmt.Fprintf(stdout, "%s: would change %s\n%s", a.DisplayName, path, guard.Diff(c.Before, c.After))
				continue
			}
			if err := c.Apply(); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", a.DisplayName, err)
				code = 1
				continue
			}
			changed++
			verb := "wrapped the local MCP servers in"
			if sub == "unwrap" {
				verb = "restored the MCP servers in"
			}
			fmt.Fprintf(stdout, "%s: %s %s\n", a.DisplayName, verb, path)
			for _, w := range c.Warnings {
				fmt.Fprintf(stdout, "  Not wrapped: %s\n", w)
			}
		}
	}
	switch {
	case *dryRun:
	case changed == 0 && code == 0:
		fmt.Fprintln(stdout, "Nothing to change.")
	case changed > 0:
		fmt.Fprintln(stdout, "Restart the agents so they start the servers again.")
		if sub == "wrap" {
			if state := daemonState(env); state != "running" {
				fmt.Fprintf(stdout, "The Privometry daemon is %s; until it runs, the shim applies fail modes. Start it with: privometry daemon install\n", state)
			}
		}
	}
	return code
}

func mcpStatus(servers []guard.MCPServer, format, home string, reg *registry.Registry, stdout io.Writer) int {
	if format == "json" {
		if servers == nil {
			servers = []guard.MCPServer{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(servers); err != nil {
			return 2
		}
		return 0
	}
	if len(servers) == 0 {
		fmt.Fprintln(stdout, "No MCP servers in your agents' user configs.")
		return 0
	}
	name := func(p contract.AgentProduct) string {
		if a, ok := reg.Get(p); ok {
			return a.DisplayName
		}
		return string(p)
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tSERVER\tSTATE\tCOMMAND\tCONFIG")
	for _, s := range servers {
		state, cmd := "not wrapped", strings.TrimSpace(s.Command+" "+strings.Join(s.Args, " "))
		switch {
		case s.Remote:
			state, cmd = "remote", "-"
		case s.Note != "":
			state = "cannot wrap: " + s.Note
		case s.Wrapped:
			state = "wrapped"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name(s.Agent), s.Name, state, truncateCmd(cmd, 60), discover.Display(s.Path, home, ""))
	}
	tw.Flush()
	return 0
}

func truncateCmd(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
