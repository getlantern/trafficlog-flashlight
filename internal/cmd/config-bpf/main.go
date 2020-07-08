// Command config-bpf is used to configure the BPF devices on a machine. It is macOS-specific. In
// the case of an error, the last line printed to stderr will describe the cause.
//
// This utility is intended to be (1) run by tlconfig on install and (2) configured as a launchd
// global daemon to run on startup. In the second case, stdout and stderr can be redirected using
// the launchd plist file. However, the files should be provided to this utility as well so that we
// can manage the size of these files. Otherwise, launchd will allow them to grow unbounded.
//
// Much of the logic and reasoning is based on Wireshark's ChmodBPF utility.
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

	"github.com/getlantern/trafficlog-flashlight/internal/exitcodes"
)

const (
	bpfGroup = "access_bpf"

	// The maximum number of BPF devices we will create, subject to system constraints.
	maxCreatedDevices = 256
)

var (
	testMode   = flag.Bool("test", false, "make no changes, just check the current installation")
	stdoutFile = flag.String("stdout", "", "path to the launchd stdout file for this utility")
	stderrFile = flag.String("stderr", "", "path to the launchd stderr file for this utility")

	bpfDeviceRegexp = regexp.MustCompile("^/dev/bpf([0-9]+)$")
)

func getMaxBPFDevices() (int, error) {
	out, err := exec.Command("sysctl", "-n", "debug.bpf_maxdevices").Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run sysctl utility: %w", err)
	}
	systemMax, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("failed to parse sysctl output as integer: %w", err)
	}
	if systemMax < maxCreatedDevices {
		return systemMax, nil
	}
	return maxCreatedDevices, nil
}

func triggerNextBPFDevice(currentDevice int) error {
	f, err := os.Open(fmt.Sprintf("/dev/bpf%d", currentDevice))
	if err != nil {
		return fmt.Errorf("failed to open current device: %w", err)
	}
	defer f.Close()
	if _, err := f.Read([]byte{}); err != nil {
		return fmt.Errorf("empty read of %s failed: %w", f.Name(), err)
	}
	return nil
}

func main() {
	flag.Parse()

	// If the stdout and stderr files have been provided, clear old data by truncating.
	if *stderrFile != "" {
		if _, err := os.Create(*stderrFile); err != nil {
			fmt.Fprintln(os.Stderr, "failed to truncate stderr file")
		}
	}
	if *stdoutFile != "" {
		if _, err := os.Create(*stdoutFile); err != nil {
			fmt.Fprintln(os.Stderr, "failed to truncate stdout file")
		}
	}

	g, err := user.LookupGroup(bpfGroup)
	if err != nil {
		exitcodes.ExitWith(fmt.Errorf("failed to look up %s: %w", bpfGroup, err))
	}
	bpfGID, err := strconv.Atoi(g.Gid)
	if err != nil {
		exitcodes.ExitWith(fmt.Errorf("failed to parse %s GID: %v", bpfGroup, err))
	}

	// Pre-create BPF devices so that we can assign the group and permissions we'd like. The logic
	// and reasoning is based on Wireshark's ChmodBPF utility.
	//
	// We create devices on a best-effort basis, ignoring most errors that we might come across.
	startDevice := 0
	err = filepath.Walk("/dev", func(path string, info os.FileInfo, err error) error {
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
	if err != nil {
		exitcodes.ExitWith(fmt.Errorf("failed to walk /dev: %w", err))
	}
	endDevice, err := getMaxBPFDevices()
	if err != nil {
		exitcodes.ExitWith(fmt.Errorf("unable to determine max BPF devices: %w", err))
	}
	if !*testMode {
		// Note that we don't check the number of devices in test mode. A failed check may trigger a
		// re-install, which in turn prompts the user. Thus we want to avoid returning failed check
		// codes unless we have to, and it is not strictly required that all of these devices exist.
		for i := startDevice; i < endDevice-1; i++ {
			if err := triggerNextBPFDevice(i); err != nil {
				// This error does not mean we should abandon the configuration process, but it does
				// mean that attempts to create further devices will also fail.
				fmt.Fprintf(os.Stderr, "failed to create device %d: %v\n", i+1, err)
				break
			}
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
		exitcodes.ExitWith(fmt.Errorf("failed to walk /dev: %w", err))
	}
	if len(bpfDevices) == 0 {
		exitcodes.ExitWith(errors.New("found no BPF devices"))
	}
	for _, dev := range bpfDevices {
		devInfo, err := os.Stat(dev)
		if err != nil {
			exitcodes.ExitWith(fmt.Errorf("failed to stat %s: %w", dev, err))
		}
		devStatT, ok := devInfo.Sys().(*syscall.Stat_t)
		if !ok {
			exitcodes.ExitWith(fmt.Errorf("failed to obtain detailed stat info for %v", dev))
		}
		if int(devStatT.Gid) != bpfGID {
			if *testMode {
				exitcodes.ExitWith(exitcodes.ErrorFailedCheckf("%s not owned by %s", dev, bpfGroup))
			}
			if err := os.Chown(dev, -1, bpfGID); err != nil {
				exitcodes.ExitWith(fmt.Errorf("failed to assign %s to %s: %w", dev, bpfGroup, err))
			}
		}
		var groupRead os.FileMode = 0b100000
		if devInfo.Mode()&groupRead != groupRead {
			if *testMode {
				exitcodes.ExitWith(exitcodes.ErrorFailedCheckf("%s does not have group read", dev))
			}
			if err := os.Chmod(dev, devInfo.Mode()|groupRead); err != nil {
				exitcodes.ExitWith(fmt.Errorf("failed to assign group read to %s: %w", dev, err))
			}
		}
	}
}
