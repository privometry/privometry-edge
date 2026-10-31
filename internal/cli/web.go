package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/privometry/privometry-edge/internal/platform"
	"github.com/privometry/privometry-edge/internal/termio"
	"github.com/privometry/privometry-edge/internal/timeline"
	"github.com/privometry/privometry-edge/internal/webui"
	timelineweb "github.com/privometry/privometry-edge/ui/timeline-web"
)

// serveTimeline runs the browser timeline on 127.0.0.1 until interrupted.
func serveTimeline(env platform.Env, port int, open bool, stdout, stderr io.Writer) int {
	dbPath, err := env.DBPath()
	if err != nil {
		return fail(stderr, err)
	}
	srv, err := webui.New(webui.Config{
		Open: func() (webui.Source, error) {
			s, err := timeline.OpenReadOnly(dbPath)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		Daemon: func() webui.Daemon {
			st, err := queryStatus(env)
			if err != nil {
				return webui.Daemon{}
			}
			return webui.Daemon{Running: true, Version: st.Version, Started: st.StartedAt.Time, Outdated: len(missingOps(st.Ops)) > 0}
		},
		Home:   env.Home,
		Assets: timelineweb.Files,
		Views:  webViews(env),
		Host:   termio.HostName(),
		User:   localUserName(),
	})
	if err != nil {
		return fail(stderr, err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fail(stderr, err)
	}
	port = l.Addr().(*net.TCPAddr).Port
	hs := &http.Server{Handler: srv.Handler(port), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute}

	url := srv.URL(port)
	fmt.Fprintf(stdout, "Timeline at %s\nThe link works only while this runs; press Ctrl+C to stop.\n", url)
	if open {
		if err := termio.OpenBrowser(url); err != nil {
			fmt.Fprintf(stderr, "privometry timeline: could not open a browser (%v); open the link above.\n", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdown)
	}()
	if err := hs.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(stderr, err)
	}
	return 0
}
