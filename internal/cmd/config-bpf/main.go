// Command config-bpf is used to configure the BPF devices on a machine. It is macOS-specific.
//
// Much of the logic and reasoning is based on Wireshark's ChmodBPF utility.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	bpfGroup = "access_bpf"

	// The maximum number of BPF devices we will create, subject to system constraints.
	maxCreatedDevices = 256
)

var bpfDeviceRegexp = regexp.MustCompile("^/dev/bpf([0-9]+)$")

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
	// We use exec.Cmd.Output over exec.Cmd.Run to populate err.Stderr.
	cmd := fmt.Sprintf(": < /dev/bpf%d > /dev/null", currentDevice)
	if _, err := exec.Command("/bin/sh", "-c", cmd).Output(); err != nil {
		return err
	}
	return nil
}

func fail(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
	os.Exit(1)
}

func failf(msg string, a ...interface{}) {
	fail(fmt.Sprintf(msg, a...))
}

func main() {
	g, err := user.LookupGroup(bpfGroup)
	if err != nil {
		failf("failed to look up %s: %v", bpfGroup, err)
	}
	bpfGID, err := strconv.Atoi(g.Gid)
	if err != nil {
		failf("failed to parse %s GID: %v", bpfGroup, err)
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
		fail("unable to determine max BPF devices:", err)
	}
	for i := startDevice; i < endDevice; i++ {
		if err := triggerNextBPFDevice(i); err != nil {
			// This error does not mean we should abandon the configuration process, but it does
			// mean that attempts to create further devices will also fail.
			fmt.Fprintf(os.Stderr, "failed to create device %d: %v", i+1, err)
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
		fail("failed to walk /dev:", err)
	}
	if len(bpfDevices) == 0 {
		fail("found no BPF devices")
	}
	for _, dev := range bpfDevices {
		devInfo, err := os.Stat(dev)
		if err != nil {
			failf("failed to stat %s: %v", dev, err)
		}
		devStatT, ok := devInfo.Sys().(*syscall.Stat_t)
		if !ok {
			fail("failed to obtain detailed stat info for", dev)
		}
		if int(devStatT.Gid) != bpfGID {
			if err := os.Chown(dev, -1, bpfGID); err != nil {
				failf("failed to assign %s to %s: %v", dev, bpfGroup, err)
			}
		}
		var groupRead os.FileMode = 0b100000
		if devInfo.Mode()&groupRead != groupRead {
			if err := os.Chmod(dev, devInfo.Mode()|groupRead); err != nil {
				failf("failed to assign group read to %s: %v", dev, err)
			}
		}
	}
}
