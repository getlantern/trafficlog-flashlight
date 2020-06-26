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

// Used by tests to modify install process. Should not contain -test flag.
var tlconfigOpts = []string{}

// Represents a tlconfig executable.
type tlconfigExec struct {
	*byteexec.Exec
	args         []string
	tmpDir       string
	prompt, icon string
}

func loadTlconfig() (*tlconfigExec, error) {
	configBinary, err := tlserverbin.Asset("tlconfig")
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}
	tmpDir, err := ioutil.TempDir("", "lantern_tmp_resources")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for binary: %w", err)
	}
	exec, err := byteexec.New(configBinary, filepath.Join(tmpDir, "tlconfig"))
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to write binary to disk: %w", err)
	}
	return &tlconfigExec{Exec: exec, tmpDir: tmpDir}, nil
}

func (e *tlconfigExec) setArgs(args ...string) {
	e.args = args
}

// Run with the input args and returned combined stdout and stderr.
func (e tlconfigExec) run(opts ...string) ([]byte, error) {
	var n int
	args := make([]string, len(tlconfigOpts)+len(opts)+len(e.args))
	for _, a := range [][]string{tlconfigOpts, opts, e.args} {
		n += copy(args[n:], a)
	}
	if e.prompt != "" {
		cmd := elevate.WithPrompt(e.prompt).WithIcon(e.icon)
		out, err := cmd.Command(e.Filename, args...).CombinedOutput()
		if err != nil && isPermissionError(err) {
			return out, ErrPermissionDenied
		}
		return out, err
	}
	return e.Command(args...).CombinedOutput()
}

// Closing the returned value will also close e.
func (e tlconfigExec) elevate(prompt, icon string) tlconfigExec {
	return tlconfigExec{e.Exec, e.args, e.tmpDir, prompt, icon}
}

func (e tlconfigExec) close() error {
	return os.RemoveAll(e.tmpDir)
}

// Install the traffic log server. This package is currently macOS only; calls to Install on other
// platforms will result in an error.
//
// This function first checks to see if the server binary is already installed in the given
// directory and if the necessary system changes have already been made. If installation or any
// system changes are necessary, the prompt and icon will be used to ask the user for elevated
// permissions. Otherwise, this function is a no-op.
//
// If the binary already exists in the input directory, but is outdated, it will be overwritten iff
// overwrite is true. Note that this will result in the user being re-prompted for permissions as
// the new binary will not inherit permissions of the old binary.
//
// A second binary, config-bpf, is installed in the same directory and according to the same rules.
// This binary is used to support a launchd user agent necessary for tlserver operation.
//
// A PermissionError is returned when the user denies permission.
func Install(dir, user, prompt, iconPath string, overwrite bool) error {
	if runtime.GOOS != "darwin" {
		return errors.New("unsupported platform")
	}

	tlserverPath, configBPFPath := filepath.Join(dir, "tlserver"), filepath.Join(dir, "config-bpf")
	tlserverBinary, err := tlserverbin.Asset("tlserver")
	if err != nil {
		return fmt.Errorf("failed to load tlserver binary: %w", err)
	}
	if err := writeFile(tlserverBinary, tlserverPath, overwrite); err != nil {
		return fmt.Errorf("failed to write tlserver binary: %w", err)
	}
	configBPFBinary, err := tlserverbin.Asset("config-bpf")
	if err != nil {
		return fmt.Errorf("failed to load config-bpf binary: %w", err)
	}
	if err := writeFile(configBPFBinary, configBPFPath, overwrite); err != nil {
		return fmt.Errorf("failed to write config-bpf binary: %w", err)
	}

	tlconfig, err := loadTlconfig()
	if err != nil {
		return fmt.Errorf("failed to load tlconfig: %w", err)
	}
	tlconfig.setArgs(tlserverPath, configBPFPath, user)
	defer tlconfig.close()

	// Check existing system configuration.
	var exitErr *exec.ExitError
	output, err := tlconfig.run("-test")
	if err != nil && errors.As(err, &exitErr) && exitErr.ExitCode() == tlconfigexit.CodeFailedCheck {
		log.Debugf("tlconfig found changes necessary: %s", string(output))
	} else if err != nil {
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(output))
		}
		return fmt.Errorf("failed to run tlconfig -test: %w", err)
	} else {
		if len(output) > 0 {
			log.Debugf("tlconfig found no necessary changes: %s", string(output))
		} else {
			log.Debug("tlconfig found no necessary changes")
		}
		return nil
	}

	// Configure system.
	output, err = tlconfig.elevate(prompt, iconPath).run()
	if err != nil {
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(output))
		}
		return fmt.Errorf("failed to run tlconfig: %w", err)
	}

	// On macOS, elevate will obscure the exit code of the command, so we can't actually know if
	// tlconfig ran successfully. We check manually by running again with -test.
	output, err = tlconfig.run("-test")
	if err != nil && errors.As(err, &exitErr) && exitErr.ExitCode() == tlconfigexit.CodeFailedCheck {
		errMsg := "unexpected configuration failure"
		if len(output) > 0 {
			errMsg = fmt.Sprintf("%s: %s", errMsg, string(output))
		}
		return errors.New(errMsg)
	} else if err != nil {
		return fmt.Errorf("failed to check success of tlconfig: %w", err)
	}

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
