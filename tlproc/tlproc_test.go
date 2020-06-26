// +build debug

package tlproc

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/getlantern/trafficlog/tltest"
	"github.com/stretchr/testify/require"
)

const (
	installDir    = "test-install"
	installPrompt = "tlproc needs to install a test binary. This should only be necessary once on this machine."
)

func TestTrafficLogProcess(t *testing.T) {
	oldOpts := tlconfigOpts
	t.Cleanup(func() { tlconfigOpts = oldOpts })
	tlconfigOpts = []string{"-config-bpf-plist-dir", installDir}

	// Make the buffers large enough that we will not lose any packets.
	const captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024

	wd, err := os.Getwd()
	require.NoError(t, err)
	path := filepath.Join(wd, installDir)

	u, err := user.Current()
	require.NoError(t, err)
	require.NoError(t, Install(path, u.Username, installPrompt, "", false))

	tl, err := New(captureBufferSize, saveBufferSize, path, nil)
	require.NoError(t, err)
	tltest.TestTrafficLog(t, tl)
}
