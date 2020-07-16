// Command tlconfig is used when installing tlserver, ensuring that the system is properly
// configured for packet capture. This includes:
//	- Configuring proper ownership and permissions for the tlserver and config-bpf binaries.
//	- Running config-bpf.
//	- Setting up config-bpf as a launchd global daemon so that it will run on startup as root.
//
// Three arguments are expected:
//  1) The path to the installation directory.
//  2) The path to a directory containing install resources. Specifically, this directory should
//     contain the tlserver and config-bpf binaries.
//  3) The path to a sentinel file for config-bpf. If this file disappears, config-bpf will remove
//     itself and its plist file on its next run.
//  4) The user for which tlserver is being installed.
//
// Currently macOS only. In the case of an error, the last line printed to stderr will describe the
// cause. Root permissions are required.
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
	"github.com/getlantern/trafficlog-flashlight/internal/tlinstall"
)

const (
	// This name is chosen to avoid conflict with existing Wireshark installations.
	bpfGroup = "access_bpf"

	// tlserver needs the setgid bit to access the BPF devices. We do not provide write permissions
	// as this binary will be owned by the user.
	tlserverPermissions = os.ModeSetgid | 0500

	// config-bpf must be readable by all or we won't be able to check the contents in test mode.
	configBPFPermissions = 0744

	// By default, config-bpf is installed as a global daemon. Overriding this is useful for
	// testing, but probably not much else as the binary will be assigned to root/wheel regardless.
	configBPFPlistDirDefault = "/Library/LaunchDaemons"

	configBPFLaunchdLabel = "org.getlantern.config-bpf"
)

var (
	testMode          = flag.Bool("test", false, "make no changes, just check the current installation")
	configBPFPlistDir = flag.String("config-bpf-plist-dir", configBPFPlistDirDefault, "directory containing the plist file")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		fmt.Fprintf(flag.CommandLine.Output(), "%s <options> [path/to/install-dir] [path/to/resources-dir] [path/to/uninstall-sentinel] [user]\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output())
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
	}
}

// The config-bpf utility is installed as a global daemon. This template is filled according to
// arguments provided at runtime, then placed in configBPFPlistDir.
const configBPFLaunchdTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
		<key>Label</key>
		<string>%s</string>
		<key>ProgramArguments</key>
		<array>
			<string>%s</string>
			<string>-stdout</string>
			<string>%s/config-bpf.stdout</string>
			<string>-stderr</string>
			<string>%s/config-bpf.stderr</string>
			<string>-plist</string>
			<string>%s</string>
			<string>-sentinel</string>
			<string>%s</string>
		</array>
		<key>RunAtLoad</key>
		<true/>
		<key>StandardOutPath</key>
		<string>%s/config-bpf.stdout</string>
		<key>StandardErrorPath</key>
		<string>%s/config-bpf.stderr</string>
	</dict>
</plist>`

func configBPFLaunchdPlistData(configBPFAbsPath, plist, sentinel, outDir string) []byte {
	return []byte(fmt.Sprintf(configBPFLaunchdTmpl,
		configBPFLaunchdLabel, configBPFAbsPath, outDir, outDir, plist, sentinel, outDir, outDir,
	))
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
	b = bytes.TrimSpace(b)
	splits := bytes.Split(b, []byte{'\n'})
	return splits[len(splits)-1]
}

// In test mode, this simply checks to see if the contents differ. If dst does not exist &&
// !testMode, it will be created with file mode 0644.
func copyFile(src, dst string, testMode bool) error {
	srcF, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", src, err)
	}
	defer srcF.Close()

	dstFlag := os.O_RDWR | os.O_CREATE
	if testMode {
		// In test mode, we may not have write permissions and we don't want to create any files.
		dstFlag = os.O_RDONLY
	}
	dstF, err := os.OpenFile(dst, dstFlag, 0644)
	if testMode && os.IsNotExist(err) {
		return exitcodes.ErrorFailedCheckf("%s does not exist", dst)
	}
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", dst, err)
	}
	defer dstF.Close()

	srcContents, err := ioutil.ReadAll(srcF)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", src, err)
	}
	dstContents, err := ioutil.ReadAll(dstF)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", dst, err)
	}
	if bytes.Equal(srcContents, dstContents) {
		return nil
	}
	if testMode {
		return exitcodes.ErrorOutdated("contents differ")
	}
	if _, err := dstF.WriteAt(srcContents, 0); err != nil {
		return fmt.Errorf("failed to write to %s: %w", dst, err)
	}
	return nil

}

// Assign the file to the user and group, assign the specified permissions.
func configureFile(info fileInfo, u user.User, g user.Group, perm os.FileMode, testMode bool) error {
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
			return exitcodes.ErrorFailedCheckf("not owned by %s and %s", u.Username, g.Name)
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

func configure(installDir, resourcesDir, plistDir, sentinel, username string, testMode bool) error {
	rDir, err := tlinstall.NewResourcesDir(resourcesDir)
	if err != nil {
		return fmt.Errorf("failed to create resources dir reference: %w", err)
	}

	u, err := user.Lookup(username)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to look up user", err)
	}
	_, err = stat(rDir.Tlserver())
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat new tlserver binary", err)
	}
	_, err = stat(rDir.ConfigBPF())
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat new config-bpf binary", err)
	}
	sentinelInfo, err := stat(sentinel)
	if err != nil {
		return exitcodes.ErrorBadInput("failed to stat sentinel file", err)
	}
	root, err := user.LookupId("0")
	if err != nil {
		return fmt.Errorf("failed to look up super user (UID 0): %w", err)
	}
	wheel, err := user.LookupGroupId("0")
	if err != nil {
		return fmt.Errorf("failed to look up superuser group (GID 0): %w", err)
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

	// In test mode, we track whether one of the binaries is outdated. If so, AND if there are no
	// other failures, then we return exitcodes.OutdatedError.
	var (
		outdatedErr  *exitcodes.OutdatedError
		outdatedFile string
	)
	isOutdatedError := func(err error, filename string) bool {
		if errors.As(err, &outdatedErr) {
			outdatedFile = filename
			return true
		}
		return false
	}

	tlserverPath := filepath.Join(installDir, "tlserver")
	configBPFPath := filepath.Join(installDir, "config-bpf")
	err = copyFile(rDir.Tlserver(), tlserverPath, testMode)
	if err != nil && !isOutdatedError(err, "tlserver") {
		if testMode {
			return fmt.Errorf("tlserver content checks failed: %w", err)
		}
		return fmt.Errorf("failed to replace current tlserver binary: %w", err)
	}
	tlserverInfo, err := stat(tlserverPath)
	if err != nil {
		return fmt.Errorf("failed to stat tlserver after copy: %w", err)
	}
	err = copyFile(rDir.ConfigBPF(), configBPFPath, testMode)
	if err != nil && !isOutdatedError(err, "config-bpf") {
		if testMode {
			return fmt.Errorf("config-bpf content checks failed: %w", err)
		}
		return fmt.Errorf("failed to replace current config-bpf binary: %w", err)
	}
	configBPFInfo, err := stat(configBPFPath)
	if err != nil {
		return fmt.Errorf("failed to stat config-bpf after copy: %w", err)
	}

	if err := configureFile(*tlserverInfo, *u, *g, tlserverPermissions, testMode); err != nil {
		if testMode {
			return fmt.Errorf("tlserver file info checks failed: %w", err)
		}
		return fmt.Errorf("failed to configure tlserver: %w", err)
	}
	// config-bpf is assigned to root/wheel because it is going to be configured to run as a global
	// daemon. This way bad actors cannot just replace the binary and run an executable as root.
	if err := configureFile(*configBPFInfo, *root, *wheel, configBPFPermissions, testMode); err != nil {
		if testMode {
			return fmt.Errorf("config-bpf file info checks failed: %w", err)
		}
		return fmt.Errorf("failed to configure config-bpf: %w", err)
	}

	// Run config-bpf. Though we will be registering this to run on login, we want the system to be
	// properly configured when tlconfig completes.
	var exitErr *exec.ExitError
	path, args := configBPFInfo.path, []string{}
	if testMode {
		// In test mode, we use the binary in the resources dir as we may not have executable
		// permissions on the "standard" one.
		path, args = rDir.ConfigBPF(), []string{"-test"}
	}
	out, err := exec.Command(path, args...).CombinedOutput()
	if err != nil && errors.As(err, &exitErr) {
		return exitcodes.ErrorFromCode(exitErr.ExitCode(), string(lastLine(out)))
	} else if err != nil {
		return fmt.Errorf("failed to run config-bpf: %w", err)
	}

	plistDir = strings.Replace(plistDir, "~", u.HomeDir, -1)
	plistFilename := fmt.Sprintf("%s/%s.plist", plistDir, configBPFLaunchdLabel)
	plistData := configBPFLaunchdPlistData(
		configBPFInfo.path, plistFilename, sentinelInfo.path, installDir)
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

	if outdatedErr != nil {
		return fmt.Errorf("%s: %w", outdatedFile, outdatedErr)
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
	installDir, resourcesDir, sentinel, username := args[0], args[1], args[2], args[3]
	if *configBPFPlistDir == "" {
		*configBPFPlistDir = configBPFPlistDirDefault
	}

	err := configure(installDir, resourcesDir, *configBPFPlistDir, sentinel, username, *testMode)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitcodes.ExitWith(fmt.Errorf("%s: %s", err.Error(), string(exitErr.Stderr)))
		}
		exitcodes.ExitWith(err)
	}
}
