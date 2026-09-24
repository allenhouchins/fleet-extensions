package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// sshdTimeout bounds each sshd invocation. A config dump is near-instant; this
// only guards against a hung process holding up the query.
const sshdTimeout = 15 * time.Second

// sshdCandidates lists where sshd lives on each platform. They are checked
// before PATH because osqueryd runs extensions with a minimal environment.
var sshdCandidates = map[string][]string{
	"darwin": {"/usr/sbin/sshd"},
	"linux":  {"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd"},
}

// unsupportedFlag matches the error sshd prints when it predates -G (added in
// OpenSSH 9.3). The wording comes from whichever getopt sshd was linked
// against: BSD libc says "illegal", glibc "invalid", OpenSSH's bundled getopt
// "unknown", and musl "unrecognized". sshd follows it with its usage text,
// which is matched as well in case a getopt words it some other way.
var unsupportedFlag = regexp.MustCompile(`(?i)(illegal|invalid|unknown|unrecognized) option(:| --) '?G'?|usage: sshd`)

type configEntry struct {
	Keyword string
	Value   string
}

// findSSHD returns the path of the sshd binary, or "" when none is installed.
func findSSHD() string {
	for _, path := range sshdCandidates[runtime.GOOS] {
		if isExecutable(path) {
			return path
		}
	}
	if path, err := exec.LookPath("sshd"); err == nil {
		return path
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// dumpConfig returns sshd's effective configuration and the arguments that
// produced it. It prefers -G, which only parses the configuration, and falls
// back to -T on sshd builds too old to have -G. -T prints the same dump but
// also loads the host keys, so it needs root and fails on a host whose keys
// have not been generated yet.
//
// A connection spec needs -T even when -G is available: despite the man page,
// every sshd from 9.3 on rejects -C unless -T is also given. With both flags,
// -G still dumps the configuration and exits before -T loads any host keys.
func dumpConfig(ctx context.Context, sshdPath, spec string) (string, []string, error) {
	args := []string{"-G"}
	if spec != "" {
		args = append(args, "-T", "-C", spec)
	}
	output, stderr, err := runSSHD(ctx, sshdPath, args)
	if err == nil {
		return output, args, nil
	}
	if !unsupportedFlag.MatchString(stderr) {
		return "", args, sshdError(sshdPath, args, stderr, err)
	}

	args = []string{"-T"}
	if spec != "" {
		args = append(args, "-C", spec)
	}
	output, stderr, err = runSSHD(ctx, sshdPath, args)
	if err != nil {
		return "", args, sshdError(sshdPath, args, stderr, err)
	}
	return output, args, nil
}

func runSSHD(ctx context.Context, sshdPath string, args []string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, sshdTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, sshdPath, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// sshdError reports what sshd printed, since the exit status alone ("exit
// status 255") says nothing about which line of the configuration is wrong.
func sshdError(sshdPath string, args []string, stderr string, err error) error {
	command := sshdPath + " " + strings.Join(args, " ")
	if msg := strings.TrimSpace(stderr); msg != "" {
		return fmt.Errorf("%s: %s", command, strings.Join(strings.Fields(msg), " "))
	}
	return fmt.Errorf("%s: %w", command, err)
}

// parseConfig splits sshd's "keyword value" dump into entries, in the order
// sshd printed them. Keywords that may repeat (HostKey, ListenAddress,
// AcceptEnv, Subsystem, ...) produce one entry per line.
//
// Keywords are lowercased: sshd printed them lowercase until OpenSSH 10.4
// switched to mixed case, and lowercasing keeps queries working on both.
func parseConfig(output string) []configEntry {
	var entries []configEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		keyword, value, _ := strings.Cut(line, " ")
		entries = append(entries, configEntry{
			Keyword: strings.ToLower(keyword),
			Value:   strings.TrimSpace(value),
		})
	}
	return entries
}
