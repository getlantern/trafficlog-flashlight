// Package tlproc provides a traffic log which runs in a separate process. This can be useful when
// the parent process does not have proper permissions for packet capture.
//
// This package is currently macOS only. The parent process must be running code signed with the
// com.getlantern.lantern identifier and a trusted anchor. Build with the tag 'debug' to create
// traffic log processes which skip peer verification.
package tlproc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/trafficlog"
	"github.com/getlantern/trafficlog-flashlight/internal/tlserverbin"
	"github.com/getlantern/trafficlog/tlhttp"
)

const (
	// Size of buffered channels readable via public API.
	channelBufferSize = 10

	// Time between polls to the process server. We only poll on start-up.
	pollWaitTime = 50 * time.Millisecond

	errorPrefix, statsPrefix = "error: ", "stats: "
)

// DefaultRequestTimeout is used when Options.RequestTimeout is not set.
const DefaultRequestTimeout = 5 * time.Second

// Options for launching a traffic log process.
type Options struct {
	trafficlog.Options

	// PathToExecutable defines the path to the traffic log executable. If the executable does not
	// already exist at this location, it will be created by New.
	//
	// If no path is specified, a file named 'tlproc' will be placed in the default location used by
	// github.com/getlantern/byteexec.New.
	PathToExecutable string

	// StartTimeout is the maximum amount of time to wait for the process to start. If unspecified,
	// no timeout will be applied.
	StartTimeout time.Duration

	// RequestTimeout is applied to every request made of the traffic log process. If unspecified,
	// DefaultRequestTimeout will be used.
	RequestTimeout time.Duration
}

func (opts Options) pathToExecutable() string {
	if opts.PathToExecutable == "" {
		// This will be treated as a relative path and placed in byteexec's default directory.
		return "tlproc"
	}
	return opts.PathToExecutable
}

func (opts Options) startTimeout() time.Duration {
	if opts.StartTimeout == 0 {
		return time.Duration(math.MaxInt64)
	}
	return opts.StartTimeout
}

func (opts Options) requestTimeout() time.Duration {
	if opts.RequestTimeout == 0 {
		return time.Duration(DefaultRequestTimeout)
	}
	return opts.RequestTimeout
}

func (opts Options) mtuLimit() int {
	if opts.MTULimit == 0 {
		return trafficlog.DefaultMaxMTU
	}
	return opts.MTULimit
}

func (opts Options) mutatorFactory() trafficlog.MutatorFactory {
	if opts.MutatorFactory == nil {
		return new(trafficlog.NoOpFactory)
	}
	return opts.MutatorFactory
}

func (opts Options) statsInterval() time.Duration {
	if opts.StatsInterval <= 0 {
		return trafficlog.DefaultStatsInterval
	}
	if opts.StatsInterval < trafficlog.MinimumStatsInterval {
		return trafficlog.MinimumStatsInterval
	}
	return opts.StatsInterval
}

// A TrafficLogProcess is a traffic log running in a separate process.
type TrafficLogProcess struct {
	tlhttp.Client

	proc      *os.Process
	errC      chan error
	statsC    chan trafficlog.CaptureStats
	closed    chan struct{}
	closeOnce sync.Once
}

// New traffic log process. The current process must be running code signed with the
// "com.getlantern.lantern" identifier and a trusted anchor.
func New(captureBytes, saveBytes int, opts *Options) (*TrafficLogProcess, error) {
	if opts == nil {
		opts = &Options{}
	}

	tlserverBinary, err := tlserverbin.Asset("tlserver")
	if err != nil {
		return nil, fmt.Errorf("failed to load trafficlog binary: %w", err)
	}
	tlserver, err := byteexec.New(tlserverBinary, opts.pathToExecutable())
	if err != nil {
		return nil, fmt.Errorf("failed to create executable: %w", err)
	}
	stripAppLayer, err := shouldStripAppLayer(opts.mutatorFactory())
	if err != nil {
		return nil, err
	}
	socket, err := newSocketFile()
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix socket file: %w", err)
	}

	cmd := tlserver.Command(
		"-socket-file", socket,
		"-capture-bytes", strconv.Itoa(captureBytes),
		"-save-bytes", strconv.Itoa(saveBytes),
		"-mtu-limit", strconv.Itoa(opts.MTULimit),
		"-stats-interval", opts.statsInterval().String(),
		"-error-prefix", errorPrefix,
		"-stats-prefix", statsPrefix,
		fmt.Sprintf("-strip-app-layer=%t", stripAppLayer),
	)
	client := newClient(socket, opts.requestTimeout())

	cmdStderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to attach to process stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start traffic log process: %w", err)
	}

	var (
		errC         = make(chan error, channelBufferSize)
		statsC       = make(chan trafficlog.CaptureStats, channelBufferSize)
		serverUp     = make(chan struct{})
		closed       = make(chan struct{})
		stderrBuf    = new(bytes.Buffer)
		stderrCopier = newCopier(cmdStderr, stderrBuf)
	)
	go func() {
		err := cmd.Wait()
		if err == nil {
			return
		}
		select {
		case <-closed:
		default:
			// TODO: this could result in send on closed channel
			errC <- fmt.Errorf("process died: %w", err)
		}
	}()
	go func() {
		if err := stderrCopier.copy(); err != nil && !errors.Is(err, os.ErrClosed) {
			stderrBuf.WriteString(fmt.Sprintf("error reading stderr: %v", err))
		}
	}()
	go func() {
		for {
			time.Sleep(pollWaitTime)
			if err = client.CheckHealth(); err == nil {
				close(serverUp)
				return
			}
		}
	}()

	select {
	case err := <-errC:
		stderrCopier.stop()
		cmd.Process.Kill()
		return nil, fmt.Errorf("error starting process: %w; stderr: %s", err, stderrBuf.String())
	case <-time.After(opts.startTimeout()):
		stderrCopier.stop()
		cmd.Process.Kill()
		return nil, fmt.Errorf("timed out waiting for process to start; stderr: %s", stderrBuf.String())
	case <-serverUp:
		stderrCopier.stop()
		cmdStderr, err := cmd.StderrPipe()
		if err != nil {
			cmd.Process.Kill()
			return nil, fmt.Errorf("failed to attach to process stderr: %w", err)
		}
		p := TrafficLogProcess{client, cmd.Process, errC, statsC, closed, sync.Once{}}
		go p.watchStderr(io.MultiReader(stderrBuf, cmdStderr))
		return &p, nil
	}
}

// Errors behaves as documented by trafficlog.TrafficLog.Errors. The set of possible errors is
// larger because there may be some errors on this channel related to things like network I/O.
func (p *TrafficLogProcess) Errors() <-chan error {
	return p.errC
}

// Stats behaves as documented by trafficlog.Trafficlog.Stats.
func (p *TrafficLogProcess) Stats() <-chan trafficlog.CaptureStats {
	return p.statsC
}

// Close kills the traffic log process. This function will always return nil after the first call.
func (p *TrafficLogProcess) Close() error {
	var err error
	p.closeOnce.Do(func() {
		close(p.closed)
		err = p.proc.Kill()
		close(p.errC)
		close(p.statsC)
	})
	return err
}

func (p *TrafficLogProcess) watchStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, errorPrefix):
			p.sendError(errors.New(strings.TrimPrefix(line, errorPrefix)))
		case strings.HasPrefix(line, statsPrefix):
			line = strings.TrimPrefix(line, statsPrefix)
			stats := new(trafficlog.CaptureStats)
			if err := json.Unmarshal([]byte(line), stats); err != nil {
				p.sendError(fmt.Errorf("failed to unmarshal stats: %w", err))
				continue
			}
			p.sendStats(*stats)
		default:
			// Other messages are sometimes printed, but we don't care about these.
		}
	}
}

func (p *TrafficLogProcess) sendError(err error) {
	select {
	case p.errC <- err:
	default:
	}
}

func (p *TrafficLogProcess) sendStats(stats trafficlog.CaptureStats) {
	select {
	case p.statsC <- stats:
	default:
	}
}

func shouldStripAppLayer(mutator trafficlog.MutatorFactory) (bool, error) {
	switch mutator.(type) {
	case trafficlog.AppStripperFactory, *trafficlog.AppStripperFactory:
		return true, nil
	case trafficlog.NoOpFactory, *trafficlog.NoOpFactory:
		return false, nil
	default:
		return false, errors.New(
			"only trafficlog.AppStripperFactory or trafficlog.NoOpFactory are allowed")
	}
}

func newSocketFile() (string, error) {
	f, err := ioutil.TempFile("", "tlproc-*.sock")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	f.Close()
	os.Remove(f.Name())
	return f.Name(), nil
}

func newClient(socketFile string, timeout time.Duration) tlhttp.Client {
	return tlhttp.Client{
		// The address does not matter, but the http library complains without one.
		ServerAddress: "tlproc",
		Scheme:        "http",
		HTTPClient: http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					// Ignore the network and address and return a Unix socket connection instead.
					return (&net.Dialer{}).DialContext(ctx, "unix", socketFile)
				},
			},
			Timeout: timeout,
		},
	}
}

type copier struct {
	from    io.ReadCloser
	to      io.Writer
	stopped chan struct{}
}

func newCopier(from io.ReadCloser, to io.Writer) copier {
	return copier{from, to, make(chan struct{})}
}

func (c copier) copy() error {
	defer close(c.stopped)
	for {
		buf := make([]byte, 100)
		n, err := c.from.Read(buf)
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}
		if _, err := c.to.Write(buf[:n]); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}
}

func (c copier) stop() {
	c.from.Close()
	<-c.stopped
}
