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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/golog"
	"github.com/getlantern/trafficlog"
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

var log = golog.LoggerFor("trafficlog-flashlight.tlproc")

// Options for launching a traffic log process.
type Options struct {
	trafficlog.Options

	// StartTimeout is the maximum amount of time to wait for the process to start. If unspecified,
	// no timeout will be applied.
	StartTimeout time.Duration

	// RequestTimeout is applied to every request made of the traffic log process. If unspecified,
	// DefaultRequestTimeout will be used.
	RequestTimeout time.Duration
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

	proc     *os.Process
	errC     chan error
	statsC   chan trafficlog.CaptureStats
	closed   chan struct{}
	closedMx sync.Mutex
}

// New traffic log process. The current process must be running code signed with the
// "com.getlantern.lantern" identifier and a trusted anchor. execPath specifies the path to the
// installation directory and should match the path previously provided to Install.
//
// Install must be invoked before the first call to New on a given machine. Installations persist
// across runtimes.
func New(captureBytes, saveBytes int, installDir string, opts *Options) (*TrafficLogProcess, error) {
	if opts == nil {
		opts = &Options{}
	}
	binPath := filepath.Join(installDir, "tlserver")
	_, err := os.Stat(binPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("executable does not exist at provided path")
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat executable: %w", err)
	}

	tlserver, err := byteexec.Existing(binPath)
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
		stderrBuf    = new(syncBuf)
		stderrCopier = newCopier(cmdStderr, stderrBuf)
		p            = TrafficLogProcess{client, cmd.Process, errC, statsC, closed, sync.Mutex{}}
	)
	go func() {
		err := cmd.Wait()
		if err == nil {
			return
		}
		p.sendError(fmt.Errorf("process died: %w", err))
	}()
	go func() {
		if err := stderrCopier.copy(); err != nil && !errors.Is(err, os.ErrClosed) {
			p.sendError(fmt.Errorf("error reading stderr: %w", err))
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
		cmd.Process.Kill()
		stderrCopier.stop()
		return nil, fmt.Errorf("error starting process: %w; stderr: %s", err, stderrBuf.String())
	case <-time.After(opts.startTimeout()):
		cmd.Process.Kill()
		stderrCopier.stop()
		return nil, fmt.Errorf("timed out waiting for process to start; stderr: %s", stderrBuf.String())
	case <-serverUp:
		rPipe, wPipe := io.Pipe()
		stderrCopier.switchWriter(wPipe)
		go p.watchStderr(io.MultiReader(stderrBuf, rPipe))
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
	p.closedMx.Lock()
	defer p.closedMx.Unlock()
	select {
	case <-p.closed:
		close(p.closed)
		close(p.errC)
		close(p.statsC)
		return p.proc.Kill()
	default:
		return nil
	}
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
	p.closedMx.Lock()
	defer p.closedMx.Unlock()
	select {
	case <-p.closed:
	default:
		select {
		case p.errC <- err:
		default:
		}
	}
}

func (p *TrafficLogProcess) sendStats(stats trafficlog.CaptureStats) {
	p.closedMx.Lock()
	defer p.closedMx.Unlock()
	select {
	case <-p.closed:
	default:
		select {
		case p.statsC <- stats:
		default:
		}
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

// Zero value is ready-to-go.
type syncBuf struct {
	buf bytes.Buffer
	sync.Mutex
}

func (sb *syncBuf) Read(b []byte) (n int, err error) {
	sb.Lock()
	n, err = sb.buf.Read(b)
	sb.Unlock()
	return
}

func (sb *syncBuf) Write(b []byte) (n int, err error) {
	sb.Lock()
	n, err = sb.buf.Write(b)
	sb.Unlock()
	return
}

func (sb *syncBuf) String() string {
	sb.Lock()
	defer sb.Unlock()
	return sb.buf.String()
}

type copier struct {
	from  io.Reader
	to    io.Writer
	stopC chan struct{}
	sync.Mutex
}

func newCopier(from io.Reader, to io.Writer) copier {
	return copier{from, to, make(chan struct{}), sync.Mutex{}}
}

func (c *copier) copy() error {
	protectedWrite := func(b []byte) (n int, err error) {
		c.Lock()
		n, err = c.to.Write(b)
		c.Unlock()
		return
	}

	buf := make([]byte, 100)
	for {
		n, err := c.from.Read(buf)
		if err != nil {
			return fmt.Errorf("read error: %w", err)
		}
		select {
		case <-c.stopC:
			return nil
		default:
			if _, err := protectedWrite(buf[:n]); err != nil {
				return fmt.Errorf("write error: %w", err)
			}
		}
	}
}

func (c *copier) switchWriter(w io.Writer) {
	c.Lock()
	c.to = w
	c.Unlock()
}

func (c *copier) stop() {
	close(c.stopC)
}
