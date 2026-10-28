// Command privometry-hook is the small client that coding agents invoke on each
// hook event: privometry-hook <agent> <event>, with the hook payload on stdin.
// See internal/hookclient.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/privometry/privometry-oss/internal/buildinfo"
	"github.com/privometry/privometry-oss/internal/hookclient"
	"github.com/privometry/privometry-oss/internal/platform"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println(buildinfo.String("privometry-hook"))
		return
	}
	env, err := platform.CurrentEnv()
	if err != nil {
		os.Exit(0) // no home directory: give no opinion rather than break the agent
	}
	opts := hookclient.Options{Env: env}
	if ms, err := strconv.Atoi(os.Getenv("PRIVOMETRY_HOOK_TIMEOUT_MS")); err == nil && ms > 0 {
		opts.Timeout = time.Duration(ms) * time.Millisecond
	}
	os.Exit(hookclient.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, opts))
}
