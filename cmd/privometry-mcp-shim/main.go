// Command privometry-mcp-shim runs a local stdio MCP server for an agent and
// checks each tool call with the Privometry daemon first. privometry mcp wrap
// writes it into agent configs; see internal/mcpshim.
//
//	privometry-mcp-shim --agent <agent> --server <name> -- <command> [args...]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/privometry/privometry-edge/internal/buildinfo"
	"github.com/privometry/privometry-edge/internal/mcpshim"
	"github.com/privometry/privometry-edge/internal/platform"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String("privometry-mcp-shim"))
		return
	}
	fs := flag.NewFlagSet("privometry-mcp-shim", flag.ContinueOnError)
	agent := fs.String("agent", "other", "agent product whose config runs this server")
	server := fs.String("server", "", "the server's name in that config")
	if err := fs.Parse(os.Args[1:]); err != nil || fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: privometry-mcp-shim --agent <agent> --server <name> -- <command> [args...]")
		os.Exit(2)
	}
	env, err := platform.CurrentEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "privometry-mcp-shim:", err)
		os.Exit(2)
	}
	// The agent stops its servers with a signal; the server gets it through
	// the context, and the shim exits with the server.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(mcpshim.Run(ctx, mcpshim.Options{Env: env, Agent: *agent, Server: *server, Command: fs.Arg(0), Args: fs.Args()[1:],
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}))
}
