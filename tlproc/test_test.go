package tlproc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTest(t *testing.T) {
	require.NoError(t, install("pretend_bin", "harryharpham", "Lantern needs permission to install diagnostic tools", ""))
}
