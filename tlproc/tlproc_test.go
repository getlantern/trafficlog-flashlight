// +build debug

package tlproc

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/getlantern/trafficlog"
	"github.com/getlantern/trafficlog/tltest"
	"github.com/stretchr/testify/require"
)

const (
	binaryPath    = "test-binary"
	installPrompt = "tlproc needs to install a test binary. This should only be necessary once on this machine."
)

func TestTrafficLogProcess(t *testing.T) {
	// Make the buffers large enough that we will not lose any packets.
	const captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024

	wd, err := os.Getwd()
	require.NoError(t, err)
	path := filepath.Join(wd, binaryPath)

	u, err := user.Current()
	require.NoError(t, err)
	require.NoError(t, Install(path, u.Username, installPrompt, "", false))

	opts := &Options{}
	opts.MTULimit = trafficlog.MTULimitNone
	tl, err := New(captureBufferSize, saveBufferSize, path, opts)
	require.NoError(t, err)
	tltest.TestTrafficLog(t, tl)
}
