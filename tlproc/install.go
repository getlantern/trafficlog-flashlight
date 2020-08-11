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
	"github.com/getlantern/trafficlog-flashlight/internal/exitcodes"
	"github.com/getlantern/trafficlog-flashlight/internal/tlinstall"
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
	prompt, icon string
}

func loadTlconfig(tmpDir string) (*tlconfigExec, error) {
	configBinary, err := tlserverbin.Asset("tlconfig")
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}
	exec, err := byteexec.New(configBinary, filepath.Join(tmpDir, "tlconfig"))
	if err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to write binary to disk: %w", err)
	}
	return &tlconfigExec{Exec: exec}, nil
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
	return tlconfigExec{e.Exec, e.args, prompt, icon}
}

// InstallOptions are used to specify optional parameters to Install.
type InstallOptions struct {
	// Overwrite specifies whether to force overwriting of the server binary. If the binary already
	// exists in the input directory, but is outdated, it will be overwritten iff Overwrite is true.
	// Note that this will result in the user being re-prompted for permissions as the new binary
	// will not inherit permissions of the old binary.
	Overwrite bool

	// UninstallSentinel is a file whose absence indicates that the traffic log server should be
	// uninstalled.
	//
	// To be more specific, on macOS, the config-bpf global daemon checks for the existence of this
	// file on each run (at system start). If config-bpf does not find the sentinel file, config-bpf
	// will delete itself and its launchd plist file.
	//
	// Defaults to the path to the current program (os.Executable).
	UninstallSentinel string
}

func (opts InstallOptions) uninstallSentinel() (string, error) {
	if opts.UninstallSentinel != "" {
		return opts.UninstallSentinel, nil
	}
	ex, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get path to executable")
	}
	return ex, nil
}

// Install the traffic log server. This package is currently macOS only; calls to Install on other
// platforms will result in an error. The install directory will be created if necessary.
//
// This function first checks to see if the server binary is already installed in the given
// directory and if the necessary system changes have already been made. If installation or any
// system changes are necessary, the prompt and icon will be used to ask the user for elevated
// permissions. Otherwise, this function is a no-op.
//
// In addition to the server binary, a second binary, config-bpf, is installed in the same directory
// and according to the same rules. This binary is used to support a launchd global daemon necessary
// for tlserver operation.
//
// A PermissionError is returned when the user denies permission.
func Install(dir, user, prompt, iconPath string, opts *InstallOptions) error {
	if runtime.GOOS != "darwin" {
		return errors.New("unsupported platform")
	}

	if opts == nil {
		opts = &InstallOptions{}
	}
	uninstallSentinel, err := opts.uninstallSentinel()
	if err != nil {
		return fmt.Errorf("failed to get uninstall sentinel: %w", err)
	}

	_, err = os.Stat(dir)
	if os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0755); err != nil {
			return fmt.Errorf("failed to create install directory: %w", err)
		}
	}

	resourcesPath, err := ioutil.TempDir("", "lantern-tmp-resources")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(resourcesPath)
	resources, err := tlinstall.NewResourcesDir(resourcesPath)
	if err != nil {
		return fmt.Errorf("failed to create reference to resources directory: %w", err)
	}

	tlserverBinary, err := tlserverbin.Asset("tlserver")
	if err != nil {
		return fmt.Errorf("failed to load tlserver binary: %w", err)
	}
	if err := ioutil.WriteFile(resources.Tlserver(), tlserverBinary, 0744); err != nil {
		return fmt.Errorf("failed to write tlserver binary to resources directory: %w", err)
	}
	configBPFBinary, err := tlserverbin.Asset("config-bpf")
	if err != nil {
		return fmt.Errorf("failed to load config-bpf binary: %w", err)
	}
	if err := ioutil.WriteFile(resources.ConfigBPF(), configBPFBinary, 0744); err != nil {
		return fmt.Errorf("failed to write config-bpf binary to resources directory: %w", err)
	}

	tlconfig, err := loadTlconfig(resourcesPath)
	if err != nil {
		return fmt.Errorf("failed to load tlconfig: %w", err)
	}
	tlconfig.setArgs(dir, resourcesPath, uninstallSentinel, user)

	// Check existing system configuration.
	var (
		exitErr               *exec.ExitError
		failedCheck, outdated bool
	)
	output, err := tlconfig.run("-test")
	if errors.As(err, &exitErr) {
		outdated = exitErr.ExitCode() == exitcodes.Outdated
		failedCheck = exitErr.ExitCode() == exitcodes.FailedCheck
	}
	switch {
	case failedCheck, outdated && opts.Overwrite:
		log.Debugf("tlconfig found changes necessary: %s", string(fmtOutputForLog(output)))
	case err == nil, outdated && !opts.Overwrite:
		if len(output) > 0 {
			log.Debugf(
				"tlconfig found no necessary changes (overwrite=%t); output: %s",
				opts.Overwrite, string(fmtOutputForLog(output)))
		} else {
			log.Debug("tlconfig found no necessary changes")
		}
		return nil
	default:
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(lastLine(output)))
		}
		return fmt.Errorf("failed to run tlconfig -test: %w", err)
	}

	// Configure system.
	output, err = tlconfig.elevate(prompt, iconPath).run()
	if err != nil {
		if len(output) > 0 {
			err = fmt.Errorf("%w: %s", err, string(lastLine(output)))
		}
		return fmt.Errorf("failed to run tlconfig: %w", err)
	}

	// On macOS, elevate will obscure the exit code of the command, so we can't actually know if
	// tlconfig ran successfully. We check manually by running again with -test.
	output, err = tlconfig.run("-test")
	if errors.As(err, &exitErr) {
		outdated = exitErr.ExitCode() == exitcodes.Outdated
		failedCheck = exitErr.ExitCode() == exitcodes.FailedCheck
	} else {
		outdated, failedCheck = false, false
	}
	switch {
	case failedCheck, outdated && opts.Overwrite:
		errMsg := "unexpected configuration failure"
		if len(output) > 0 {
			errMsg = fmt.Sprintf("%s: %s", errMsg, string(lastLine(output)))
		}
		return errors.New(errMsg)
	case err != nil:
		errMsg := "unexpected failure running post-install check"
		if len(output) > 0 {
			errMsg = fmt.Sprintf("%s: %s", errMsg, string(lastLine(output)))
		}
		return errors.New(errMsg)
	}

	successLog := "tlserver installed successfully"
	if len(output) > 0 {
		successLog = fmt.Sprintf("%s: %s", successLog, string(fmtOutputForLog(output)))
	}
	log.Debug(successLog)
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

func fmtOutputForLog(cmdOutput []byte) []byte {
	cmdOutput = bytes.TrimSpace(cmdOutput)
	splits := bytes.Split(cmdOutput, []byte{'\n'})
	if len(splits) == 1 {
		return splits[0]
	}
	b := make([]byte, len(cmdOutput)+1)
	b[0] = '\n'
	copy(b[1:], cmdOutput)
	return b
}

func lastLine(b []byte) []byte {
	b = bytes.TrimSpace(b)
	splits := bytes.Split(b, []byte{'\n'})
	return splits[len(splits)-1]
}
