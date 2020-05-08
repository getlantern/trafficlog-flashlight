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
	"syscall"
)

// TODO: may need to force-create BPF devices. See:
// https://github.com/wireshark/wireshark/blob/master/packaging/macosx/ChmodBPF/root/Library/Application%20Support/Wireshark/ChmodBPF/ChmodBPF

// TODO: may need to install a launch daemon alá Wireshark's ChmodBPF

// TODO: coordinate exit codes with tlproc

const (
	bpfGroup = "access_bpf"

	// We define proper permissions as having only the user-execute bit and the setgid bit.
	binPermissions = os.ModeSetgid | 0100
)

var (
	testMode = flag.Bool("test", false, "make no changes, just check the current installation")

	bpfDeviceRegexp = regexp.MustCompile("^/dev/bpf[0-9]+$")
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

func fail(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func createGroup(name string) (*user.Group, error) {
	cmd := exec.Command("dseditgroup", "-o", "create", "-r", name, name)
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		exec.Command("dseditgroup", "-o", "delete", name).Run()
		return nil, fmt.Errorf("look up failed: %w", err)
	}
	return g, nil
}

func configure(binary, username string, testMode bool) error {
	userAccount, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to look up user: %w", err)
	}
	binInfo, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("failed to stat binary: %w", err)
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
		fmt.Printf("error type: %T\n", err)
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
	if binInfo.Mode() != binPermissions {
		if testMode {
			return failedCheckf("%s does not have proper permissions", binary)
		}
		if err := os.Chmod(binary, binPermissions); err != nil {
			return fmt.Errorf("failed to assign proper permissions to binary: %w", err)
		}
	}
	return nil
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		fail("expects two arguments: the path to the binary and the user")
	}
	binPath, username := args[0], args[1]
	if err := configure(binPath, username, *testMode); err != nil {
		// TODO: print stderr if included in err (e.g. is exec.ExitError)
		fail(err)
	}
	if !*testMode {
		if err := configure(binPath, username, true); err != nil {
			// TODO: print stderr if included in err  (e.g. is exec.ExitError)
			fail("unexpected configuration failure:", err)
		}
	}
}
