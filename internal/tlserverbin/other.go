// +build !darwin !amd64

package tlserverbin

import "errors"

// Asset is not supported on this platform.
func Asset(_ string) ([]byte, error) {
	return nil, errors.New("unsupported platform")
}
