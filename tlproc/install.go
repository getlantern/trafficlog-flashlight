package tlproc

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/elevate"
	"github.com/getlantern/trafficlog-flashlight/internal/tlconfigexit"
	"github.com/getlantern/trafficlog-flashlight/internal/tlserverbin"
)

// ErrPermissionDenied is returned by Install when the user denies permission to the installer upon
// being prompted. This is currently only supported on macOS.
var ErrPermissionDenied = errors.New("user denied permission")

// Install the traffic log server. This function first checks to see if the server binary is already
// installed at the given path and if the necessary system changes have already been made. If
// installation or any system changes are necessary, the prompt and icon will be used to ask the
// user for elevated permissions. Otherwise, this function is a no-op.
//
// If the binary already exists at the input path, but is outdated, it will be overwritten iff
// overwrite is true. Note that this will result in the user being re-prompted for permissions as
// the new binary will not inherit permissions of the old binary.
//
// On supported platforms, a PermissionError is returned when the user denies permission.
func Install(path, user, prompt, iconPath string, overwrite bool) error {
	tlserverBinary, err := tlserverbin.Asset("tlserver")
	if err != nil {
		return fmt.Errorf("failed to load tlserver binary: %w", err)
	}
	if err := writeFile(tlserverBinary, path, overwrite); err != nil {
		return fmt.Errorf("failed to write tlserver binary: %w", err)
	}

	tmpDir, err := ioutil.TempDir("", "lantern_tmp_resources")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for tlconfig binary: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	configBinary, err := tlserverbin.Asset("tlconfig")
	if err != nil {
		return fmt.Errorf("failed to load tlconfig binary: %w", err)
	}
	configExec, err := byteexec.New(configBinary, filepath.Join(tmpDir, "tlconfig"))
	if err != nil {
		return fmt.Errorf("failed to write tlconfig binary to disk: %w", err)
	}

	// Check existing system configuration.
	var exitErr *exec.ExitError
	output, err := configExec.Command("-test", path, user).CombinedOutput()
	if err != nil && errors.As(err, &exitErr) && exitErr.ExitCode() == tlconfigexit.CodeFailedCheck {
		log.Debugf("tlconfig found changes necessary:\n%s", string(output))
	} else if err != nil {
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(output))
		}
		return fmt.Errorf("failed to run tlconfig -test: %w", err)
	} else {
		log.Debugf("tlconfig found no necessary changes:\n%s", string(output))
		return nil
	}

	// Configure system.
	output, err = elevateCommand(prompt, iconPath, configExec.Filename, path, user)
	if err != nil {
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(output))
		}
		return fmt.Errorf("failed to run tlconfig: %w", err)
	}

	// TODO: we don't actually know this without consulting the output of the command (since
	// cocoasudo obscures the exit code).
	successLog := "tlserver installed successfully"
	if len(output) > 0 {
		successLog = fmt.Sprintf("%s:\n%s", successLog, string(output))
	}
	log.Debug(successLog)
	return nil
}

// Writes to the path if:
//	no such file exists || (existing file differs && overwrite)
func writeFile(contents []byte, path string, overwrite bool) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0744)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		if err := ioutil.WriteFile(path, contents, 0744); err != nil {
			return fmt.Errorf("failed to create and write: %w", err)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to open for reading: %w", err)
	}
	defer f.Close()

	if !overwrite {
		return nil
	}
	current, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}
	if bytes.Equal(current, contents) {
		return nil
	}
	if _, err := f.WriteAt(contents, 0); err != nil {
		return fmt.Errorf("failed to overwrite: %w", err)
	}
	return nil
}

// Prompts the user for permission and returns the combined stdout and stderr. On supported
// platforms, a PermissionError is returned when the user denies permission.
func elevateCommand(prompt, icon, command string, args ...string) ([]byte, error) {
	cmd := elevate.WithPrompt(prompt).WithIcon(icon)
	out, err := cmd.Command(command, args...).CombinedOutput()
	if err != nil && isPermissionError(err) {
		return out, ErrPermissionDenied
	}
	return out, err
}

func isPermissionError(elevateErr error) bool {
	if runtime.GOOS != "darwin" {
		log.Debugf("unable to decode elevate errors on %s", runtime.GOOS)
		return false
	}

	// On macOS, elevate will return an exec.ExitError in 2 scenarios: (1) if the binary does not
	// exist or (2) if the user hits "cancel" when prompted for permissions. Because we create the
	// binary ourselves, we can be reasonably sure that this is the second case.
	var exitErr *exec.ExitError
	return errors.As(elevateErr, &exitErr)
}
