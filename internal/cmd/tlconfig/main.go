// Command tlconfig is used when installing tlserver, ensuring that system permissions are
// configured properly for packet capture.
//
// Expects two arguments: the first should be the path to the binary and the second should be the
// user for which tlserver is being installed. The test flag (-test) can be used to check that the
// binary is installed and permissions are properly configured.
//
// Currently macOS only.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/getlantern/trafficlog-flashlight/internal/tlconfigexit"
)

// TODO: may need to install a launch daemon alá Wireshark's ChmodBPF
// 	- Think about whether we still need test mode in this scenario

const (
	bpfGroup = "access_bpf"

	// We define proper permissions as having user rwx and the setgid bit.
	properBinPermissions = os.ModeSetgid | 0700

	// The maximum number of BPF devices we will create, subject to system constraints.
	maxCreatedDevices = 256
)

var (
	testMode = flag.Bool("test", false, "make no changes, just check the current installation")

	bpfDeviceRegexp = regexp.MustCompile("^/dev/bpf([0-9]+)$")
)

type errorFailedCheck struct {
	msg string
}

func failedCheck(msg string) errorFailedCheck {
	return errorFailedCheck{msg}
}

func failedCheckf(msg string, a ...interface{}) errorFailedCheck {
	return failedCheck(fmt.Sprintf(msg, a...))
}

func (e errorFailedCheck) Error() string {
	return e.msg
}

type errorBadInput struct {
	msg   string
	cause error
}

func badInput(msg string, cause error) errorBadInput {
	return errorBadInput{msg, cause}
}

func (e errorBadInput) Error() string {
	if e.cause == nil {
		return e.msg
	}
	return fmt.Sprintf("%s: %v", e.msg, e.cause)
}

func (e errorBadInput) Unwrap() error {
	return e.cause
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	switch {
	case errors.As(err, new(errorBadInput)):
		os.Exit(tlconfigexit.CodeBadInput)
	case errors.As(err, new(errorFailedCheck)):
		os.Exit(tlconfigexit.CodeFailedCheck)
	default:
		os.Exit(tlconfigexit.CodeUnexpectedFailure)
	}
}

func createGroup(name string) (*user.Group, error) {
	cmd := exec.Command("dseditgroup", "-o", "create", "-r", name, name)
	// We use cmd.Output over cmd.Run to populate err.Stderr.
	if _, err := cmd.Output(); err != nil {
		return nil, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		exec.Command("dseditgroup", "-o", "delete", name).Run()
		return nil, fmt.Errorf("look up failed: %w", err)
	}
	return g, nil
}

func getMaxBPFDevices() (int, error) {
	out, err := exec.Command("sysctl", "-n", "debug.bpf_maxdevices").Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run sysctl utility: %w", err)
	}
	sysctlMax, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("failed to parse sysctl output as integer: %w", err)
	}
	if sysctlMax < maxCreatedDevices {
		return sysctlMax, nil
	}
	return maxCreatedDevices, nil
}

func triggerNextBPFDevice(currentDevice int) error {
	// The command used to trigger device creation is taken from Wireshark's ChmodBPF utility.
	// We use exec.Cmd.Output over exec.Cmd.Run to populate err.Stderr.
	cmd := fmt.Sprintf(": < /dev/bpf%d > /dev/null", currentDevice)
	if _, err := exec.Command("/bin/sh", "-c", cmd).Output(); err != nil {
		return err
	}
	return nil
}

func configure(binary, username string, testMode bool) error {
	userAccount, err := user.Lookup(username)
	if err != nil {
		return badInput("failed to look up user", err)
	}
	binInfo, err := os.Stat(binary)
	if err != nil {
		return badInput("failed to stat binary", err)
	}
	binStatT, ok := binInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to obtain detailed stat info on binary")
	}
	binUID, binGID := int(binStatT.Uid), int(binStatT.Gid)

	// Create the BPF group.
	group, err := user.LookupGroup(bpfGroup)
	switch {
	case err == nil:
		// Nothing to do.
	case !errors.As(err, new(user.UnknownGroupError)):
		return fmt.Errorf("failed to look up %s: %w", bpfGroup, err)
	case errors.As(err, new(user.UnknownGroupError)) && testMode:
		return failedCheckf("%s does not exist", bpfGroup)
	case errors.As(err, new(user.UnknownGroupError)) && !testMode:
		group, err = createGroup(bpfGroup)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", bpfGroup, err)
		}
	}

	// Assign the binary to the user and the BPF group.
	userUID, err := strconv.Atoi(userAccount.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID: %w", err)
	}
	bpfGID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID: %w", err)
	}
	if binUID != userUID || binGID != bpfGID {
		if testMode {
			return failedCheckf("binary not owned by %s and %s", username, bpfGroup)
		}
		if err := os.Chown(binary, userUID, bpfGID); err != nil {
			return fmt.Errorf("failed to change binary ownership: %w", err)
		}
	}

	// Pre-create BPF devices so that we can assign the group and permissions we'd like. The logic
	// and reasoning is based on Wireshark's ChmodBPF utility.
	//
	// We create devices on a best-effort basis, ignoring most errors that we might come across.
	startDevice := 0
	filepath.Walk("/dev", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != "/dev" {
			return filepath.SkipDir
		}
		if submatches := bpfDeviceRegexp.FindStringSubmatch(path); len(submatches) >= 2 {
			dev, err := strconv.Atoi(submatches[1])
			if err == nil && dev > startDevice {
				startDevice = dev
			}
		}
		return nil
	})
	endDevice, err := getMaxBPFDevices()
	if err != nil {
		return fmt.Errorf("unable to determine max BPF devices: %w", err)
	}
	if testMode && startDevice < endDevice {
		return failedCheckf("need to create %d more BPF devices", endDevice-startDevice)
	}
	for i := startDevice; i < endDevice; i++ {
		if err := triggerNextBPFDevice(i); err != nil {
			// This error does not mean we should abandon the configuration process, but it does
			// mean that attempts to create further devices will also fail.
			break
		}
	}

	// Assign all BPF devices to the BPF group and ensure that all have group read permissions.
	bpfDevices := []string{}
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != "/dev" {
			return filepath.SkipDir
		}
		if bpfDeviceRegexp.MatchString(path) {
			bpfDevices = append(bpfDevices, path)
		}
		return nil
	}
	if err := filepath.Walk("/dev", walkFn); err != nil {
		return fmt.Errorf("failed to walk /dev: %w", err)
	}
	if len(bpfDevices) == 0 {
		return errors.New("found no BPF devices")
	}
	for _, dev := range bpfDevices {
		devInfo, err := os.Stat(dev)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", dev, err)
		}
		devStatT, ok := devInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("failed to obtain detailed stat info for %s", dev)
		}
		if int(devStatT.Gid) != bpfGID {
			if testMode {
				return failedCheckf("%s not owned by %s", dev, bpfGroup)
			}
			if err := os.Chown(dev, -1, bpfGID); err != nil {
				return fmt.Errorf("failed to assign %s to %s: %w", dev, bpfGroup, err)
			}
		}
		var groupRead os.FileMode = 0b100000
		if devInfo.Mode()&groupRead != groupRead {
			if testMode {
				return failedCheckf("%s does not have group read permissions", dev)
			}
			if err := os.Chmod(dev, devInfo.Mode()|groupRead); err != nil {
				return fmt.Errorf("failed to assign group read to %s: %w", dev, err)
			}
		}
	}

	// Set proper permissions for the binary.
	binInfo, err = os.Stat(binary)
	if err != nil {
		return fmt.Errorf("failed to stat binary: %w", err)
	}
	if binInfo.Mode() != properBinPermissions {
		if testMode {
			return failedCheckf("%s does not have proper permissions", binary)
		}
		if err := os.Chmod(binary, properBinPermissions); err != nil {
			return fmt.Errorf("failed to assign proper permissions to binary: %w", err)
		}
		// chmod (even run directly) can silently fail to flip the setgid bit.
		binInfo, err = os.Stat(binary)
		if err != nil {
			return fmt.Errorf("failed to stat binary to check chmod success: %w", err)
		}
		if binInfo.Mode() != properBinPermissions {
			return fmt.Errorf("failed to assign proper permissions to binary (silent chmod failure)")
		}
	}
	return nil
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fail(badInput("expects two arguments: the path to the binary and the user", nil))
	}
	binPath, username := args[0], args[1]
	if err := configure(binPath, username, *testMode); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			fail(fmt.Errorf("%s: %s", err.Error(), string(exitErr.Stderr)))
		}
		fail(err)
	}
}
