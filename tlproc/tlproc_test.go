// +build debug

package tlproc

import (
	"testing"

	"github.com/getlantern/trafficlog"
	"github.com/getlantern/trafficlog/tltest"
	"github.com/stretchr/testify/require"
)

func TestTrafficLogProcess(t *testing.T) {
	// Make the buffers large enough that we will not lose any packets.
	const captureBufferSize, saveBufferSize = 1024 * 1024, 1024 * 1024

	opts := &Options{}
	opts.MTULimit = trafficlog.MTULimitNone
	tl, err := New(captureBufferSize, saveBufferSize, opts)
	require.NoError(t, err)
	tltest.TestTrafficLog(t, tl)
}
