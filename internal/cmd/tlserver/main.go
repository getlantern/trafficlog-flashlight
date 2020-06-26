// Command tlserver starts a traffic log server. This server uses HTTP over Unix domain sockets and
// authenticates peers using authipc. Specifically, peer processes must be running code signed with
// the com.getlantern.lantern identifier and a trusted anchor. This server is macOS only.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/getlantern/authipc"
	"github.com/getlantern/trafficlog"
	"github.com/getlantern/trafficlog/tlhttp"
)

// Peers must be running code signed with the Lantern developer certificate. This is hard-coded as
// otherwise someone could simply run the server with a common name of their choosing.
const lanternCertCommonName = "Developer ID Application: Innovate Labs LLC (4FYC28AXA2)"

// Set to true or build with '-tags debug' to disable peer authentication.
var debugBuild = false

var (
	socketFile    = flag.String("socket-file", "", "file to listen on; should not exist")
	captureBytes  = flag.Int("capture-bytes", 0, "size of the capture buffer")
	saveBytes     = flag.Int("save-bytes", 0, "size of the save buffer")
	statsInterval = flag.Duration("stats-interval", trafficlog.DefaultStatsInterval, "print stats at this rate")
	stripAppLayer = flag.Bool("strip-app-layer", false, "strip application-layer data")
	errorPrefix   = flag.String("error-prefix", "", "prefix for error logs")
	statsPrefix   = flag.String("stats-prefix", "", "prefix for stat logs")
)

func logError(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
}

func fail(a ...interface{}) {
	logError(a...)
	os.Exit(1)
}

type loggingConn struct {
	*authipc.Conn
	logAuthFailureOnce sync.Once
}

func (lc *loggingConn) Read(b []byte) (n int, err error) {
	n, err = lc.Conn.Read(b)
	if err != nil && errors.As(err, new(authipc.AuthError)) {
		lc.logAuthFailureOnce.Do(func() { fmt.Fprintln(os.Stderr, err) })
	}
	return
}

func (lc *loggingConn) Write(b []byte) (n int, err error) {
	n, err = lc.Conn.Write(b)
	if err != nil && errors.As(err, new(authipc.AuthError)) {
		lc.logAuthFailureOnce.Do(func() { fmt.Fprint(os.Stderr, err) })
	}
	return
}

type loggingListener struct {
	net.Listener
}

func (l loggingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	if authConn, ok := c.(*authipc.Conn); ok {
		return &loggingConn{Conn: authConn}, nil
	}
	return c, err
}

func main() {
	flag.Parse()
	if *captureBytes == 0 {
		fail("capture-bytes must be provided")
	}
	if *saveBytes == 0 {
		fail("save-bytes must be provided")
	}

	var mutator trafficlog.MutatorFactory = new(trafficlog.NoOpFactory)
	if *stripAppLayer {
		mutator = new(trafficlog.AppStripperFactory)
	}

	tl := trafficlog.New(*captureBytes, *saveBytes, &trafficlog.Options{
		StatsInterval:  *statsInterval,
		MutatorFactory: mutator,
	})
	go func() {
		for {
			select {
			case err := <-tl.Errors():
				fmt.Fprintf(os.Stderr, "%s%v\n", *errorPrefix, err)
			case stats := <-tl.Stats():
				b, err := json.Marshal(stats)
				if err != nil {
					err := fmt.Errorf("failed to marshal stats: %w", err)
					fmt.Fprintf(os.Stderr, "%s%v\n", *errorPrefix, err)
					continue
				}
				fmt.Fprintf(os.Stderr, "%s%s\n", *statsPrefix, string(b))
			}
		}
	}()

	// Note that we do not need to set an address as we are communicating over Unix domain sockets.
	s := http.Server{Handler: tlhttp.RequestHandler(tl, os.Stderr)}
	v := authipc.NewSignerVerifier(lanternCertCommonName)
	if debugBuild {
		fmt.Fprintln(os.Stdout, "WARNING: this is a debug build; peer authentication is disabled")
		v = func(_ authipc.ProcessInfo) error { return nil }
	}
	l, err := authipc.Listen(*socketFile, v)
	if err != nil {
		fail("failed to start authipc listener:", err)
	}
	defer l.Close()

	fmt.Fprintln(os.Stdout, "Starting server at", l.Addr().String())
	log.Fatal(s.Serve(loggingListener{l}))
}
