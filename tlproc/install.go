package tlproc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/elevate"
	"github.com/getlantern/trafficlog-flashlight/internal/tlserverbin"
)

// Installs the traffic log server. First checks to see if the server is already installed at the
// given path and if the necessary system changes have already been made. If installation or any
// system changes are necessary, the prompt and icon will be used to ask the user for elevated
// permissions.
func install(path, user, prompt, iconPath string) error {
	tmpDir, err := ioutil.TempDir("", "lantern_tmp_resources")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for install binary: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	installBinary, err := tlserverbin.Asset("install_tlserver.sh")
	if err != nil {
		return fmt.Errorf("failed to load install binary: %w", err)
	}
	installExec, err := byteexec.New(installBinary, fmt.Sprintf("%s/install_tlserver.sh", tmpDir))
	if err != nil {
		return fmt.Errorf("failed to write install binary to disk: %w", err)
	}
	var exitErr *exec.ExitError
	output, err := installExec.Command("--test", path, user).CombinedOutput()
	if err != nil && errors.As(err, &exitErr) {
		log.Debugf("install script found changes necessary:\n%s", string(output))
	} else if err != nil {
		return fmt.Errorf("failed to run install script with --test flag: %w", err)
	} else {
		log.Debugf("install script found no necessary changes:\n%s", string(output))
		return nil
	}
	installCmd := elevate.WithPrompt(prompt).WithIcon(iconPath)
	output, err = installCmd.Command(installExec.Filename, path, user).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	log.Debugf("tlserver installed successfully:\n%s", string(output))
	return nil
}
