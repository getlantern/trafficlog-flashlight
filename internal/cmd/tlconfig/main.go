// Command tlconfig is used when installing tlserver, ensuring that the system is properly
// configured for packet capture. This includes:
//	- Configuring proper permissions for the tlserver and config-bpf binaries.
//	- Running config-bpf.
//	- Setting up config-bpf as a launchd user agent so that it will run on login.
//
// Three arguments are expected:
//	1) The path to the tlserver binary.
//	3) The path to the config-bpf binary.
//	2) The user for which tlserver is being installed.
//
// Currently macOS only. In the case of an error, the last line printed to stderr will describe the
// cause.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/getlantern/trafficlog-flashlight/internal/exitcodes"
)

const (
	// This name is chosen to avoid conflict with existing Wireshark installations.
	bpfGroup = "access_bpf"

	// We define proper permissions as having user rwx and the setgid bit.
	properBinPermissions = os.ModeSetgid | 0700

	// The maximum number of BPF devices we will create, subject to system constraints.
	maxCreatedDevices = 256

	// Special values representing default values.
	configBPFParentDir       = "<parent of config-bpf>"
	configBPFPlistDirDefault = "~/Library/LaunchAgents"

	configBPFLaunchdLabel = "org.getlantern.config-bpf"
)

var (
	testMode          = flag.Bool("test", false, "make no changes, just check the current installation")
	configBPFOutDir   = flag.String("config-bpf-out", configBPFParentDir, "directory to which stdout and stderr should be written")
	configBPFPlistDir = flag.String("config-bpf-plist-dir", configBPFPlistDirDefault, "directory containing the plist file")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintf(flag.CommandLine.Output(), "%s <options> [path/to/tlserver] [path/to/config-bpf] [user]\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
	}
}

// The config-bpf utility is installed as a launch agent. This template is filled according to
// arguments provided at runtime, then placed in ~/Library/LaunchAgents.
const configBPFLaunchdTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
        <key>Label</key>
        <string>%s</string>
        <key>Program</key>
        <string>%s</string>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardOutPath</key>
        <string>%s/config-bpf.stdout</string>
        <key>StandardErrorPath</key>
        <string>%s/config-bpf.stderr</string>
	</dict>
</plist>`

func configBPFLaunchdPlistData(configBPFAbsPath, outDir string) []byte {
	return []byte(fmt.Sprintf(configBPFLaunchdTmpl, configBPFLaunchdLabel, configBPFAbsPath, outDir, outDir))
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

type fileInfo struct {
	os.FileInfo

	// absolute
	path string
}

func stat(path string) (*fileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("unable to obtain absolute path: %w", err)
	}
	return &fileInfo{fi, path}, nil
}

func (fi *fileInfo) refresh() error {
	_fi, err := os.Stat(fi.path)
	if err != nil {
		return err
	}
	fi.FileInfo = _fi
	return nil
}

func lastLine(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if b[0] == '\n' {
		return lastLine(b[1:])
	}
	if b[len(b)-1] == '\n' {
		return lastLine(b[:len(b)-1])
	}
	splits := bytes.Split(b, []byte{'\n'})
	return splits[len(splits)-1]
}

// Assign the binary to the user and group, assign the specified permissions.
func configureBinary(info fileInfo, u user.User, g user.Group, perm os.FileMode, testMode bool) error {
	statT, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to obtain detailed stat info")
	}
	binUID, binGID := int(statT.Uid), int(statT.Gid)

	// Assign to the user and group.
	userUID, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID: %w", err)
	}
	bpfGID, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID: %w", err)
	}
	if binUID != userUID || binGID != bpfGID {
		if testMode {
			return exitcodes.ErrorFailedCheckf("not owned by %s and %s", u.Username, bpfGroup)
		}
		if err := os.Chown(info.path, userUID, bpfGID); err != nil {
			return fmt.Errorf("failed to change ownership: %w", err)
		}
	}

	// Set specified permissions. We need to stat again because we may have changed ownership.
	if err := info.refresh(); err != nil {
		return fmt.Errorf("failed to re-stat: %w", err)
	}
	if info.Mode() != perm {
		if testMode {
			return exitcodes.ErrorFailedCheckf("improper permissions: %v", info.Mode())
		}
		if err := os.Chmod(info.path, perm); err != nil {
			return fmt.Errorf("failed to assign proper permissions: %w", err)
		}
		// chmod (even run directly) can silently fail to flip the setgid bit.
		if err := info.refresh(); err != nil {
			return fmt.Errorf("failed to check chmod success via stat: %w", err)
		}
		if info.Mode() != perm {
			return fmt.Errorf("failed to assign proper permissions: silent chmod failure")
		}
	}
	return nil
}

func configure(tlserver, configBPF, configBPFOutDir, configBPFPlistDir, username string, testMode bool) error {
	u, err := user.Lookup(username)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to look up user", err)
	}
	tlserverInfo, err := stat(tlserver)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat tlserver binary", err)
	}
	configBPFInfo, err := stat(configBPF)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat config-bpf binary", err)
	}
	configBPFOutDirInfo, err := stat(configBPFOutDir)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat config-bpf output directory", err)
	}

	// Create the BPF group.
	g, err := user.LookupGroup(bpfGroup)
	switch {
	case err == nil:
		// Nothing to do.
	case !errors.As(err, new(user.UnknownGroupError)):
		return fmt.Errorf("failed to look up %s: %w", bpfGroup, err)
	case errors.As(err, new(user.UnknownGroupError)) && testMode:
		return exitcodes.ErrorFailedCheckf("%s does not exist", bpfGroup)
	case errors.As(err, new(user.UnknownGroupError)) && !testMode:
		g, err = createGroup(bpfGroup)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", bpfGroup, err)
		}
	}

	if err := configureBinary(*tlserverInfo, *u, *g, properBinPermissions, testMode); err != nil {
		if testMode {
			return fmt.Errorf("tlserver checks failed: %w", err)
		}
		return fmt.Errorf("failed to configure tlserver: %w", err)
	}
	if err := configureBinary(*configBPFInfo, *u, *g, properBinPermissions, testMode); err != nil {
		if testMode {
			return fmt.Errorf("config-bpf checks failed: %w", err)
		}
		return fmt.Errorf("failed to configure config-bpf: %w", err)
	}

	// Run config-bpf. Though we will be registering this to run on login, we want the system to be
	// properly configured when tlconfig completes.
	var exitErr *exec.ExitError
	args := []string{}
	if testMode {
		args = []string{"-test"}
	}
	out, err := exec.Command(configBPFInfo.path, args...).CombinedOutput()
	if err != nil && errors.As(err, &exitErr) {
		return exitcodes.ErrorFromCode(exitErr.ExitCode(), string(lastLine(out)))
	} else if err != nil {
		return fmt.Errorf("failed to run config-bpf: %w", err)
	}

	plistData := configBPFLaunchdPlistData(configBPFInfo.path, configBPFOutDirInfo.path)
	plistDir := strings.Replace(configBPFPlistDir, "~", u.HomeDir, -1)
	plistFilename := fmt.Sprintf("%s/%s.plist", plistDir, configBPFLaunchdLabel)
	if testMode {
		actualData, err := ioutil.ReadFile(plistFilename)
		if os.IsNotExist(err) {
			return exitcodes.ErrorFailedCheck("no launchd file found for config-bpf")
		}
		if err != nil {
			return fmt.Errorf("failed to read existing launchd file for config-bpf: %w", err)
		}
		if !bytes.Equal(plistData, actualData) {
			return exitcodes.ErrorFailedCheck("existing launchd file for config-bpf differs from expected")
		}
	} else {
		if err := ioutil.WriteFile(plistFilename, plistData, 0644); err != nil {
			return fmt.Errorf("failed to write config-bpf's launchd file: %w", err)
		}
	}

	return nil
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) < 3 {
		flag.Usage()
		os.Exit(exitcodes.BadInput)
	}
	tlserverPath, configBPFPath, username := args[0], args[1], args[2]
	if *configBPFOutDir == configBPFParentDir || *configBPFOutDir == "" {
		*configBPFOutDir = filepath.Dir(configBPFPath)
	}
	if *configBPFPlistDir == "" {
		*configBPFPlistDir = configBPFPlistDirDefault
	}

	err := configure(
		tlserverPath, configBPFPath, *configBPFOutDir, *configBPFPlistDir, username, *testMode)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitcodes.ExitWith(fmt.Errorf("%s: %s", err.Error(), string(exitErr.Stderr)))
		}
		exitcodes.ExitWith(err)
	}
}
