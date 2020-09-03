// Package tlinstall is used to coordinate specifics of tlserver installs.
package tlinstall

import (
	"fmt"
	"path/filepath"
)

// ResourcesDir holds installation resources.
type ResourcesDir struct {
	// Absolute.
	dir string
}

// NewResourcesDir return a ResourcesDir reference for the provided path. The directory is not
// created nor is its existence verified.
func NewResourcesDir(path string) (*ResourcesDir, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("unable to determine absolute path: %w", err)
	}
	return &ResourcesDir{abs}, nil
}

// Tlserver provides the expected absolute path to the tlserver binary.
func (rd ResourcesDir) Tlserver() string {
	return filepath.Join(rd.dir, "tlserver")
}

// ConfigBPF provides the expected absolute path to the config-bpf binary.
func (rd ResourcesDir) ConfigBPF() string {
	return filepath.Join(rd.dir, "config-bpf")
}
