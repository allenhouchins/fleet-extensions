package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"brew_outdated",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"brew_outdated",
		brewOutdatedColumns(),
		generateBrewOutdated,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func brewOutdatedColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("installed_version"),
		table.TextColumn("latest_version"),
	}
}

func generateBrewOutdated(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	// Find brew binary
	brewPath, err := findBrewBinary()
	if err != nil {
		log.Printf("brew_outdated: could not find brew binary: %v", err)
		return results, nil
	}
	log.Printf("brew_outdated: found brew binary at: %s", brewPath)

	// Find Homebrew owner to run command as non-root user
	// This follows osquery best practices: run as the user who owns the tool
	brewOwner, err := findHomebrewOwner(brewPath)
	if err != nil {
		log.Printf("brew_outdated: could not determine Homebrew owner: %v", err)
		return results, nil
	}
	log.Printf("brew_outdated: Homebrew owner: %s", brewOwner)

	// Check if we're already running as the brew owner
	currentUser, err := user.Current()
	if err != nil {
		log.Printf("brew_outdated: could not determine current user: %v", err)
		return results, nil
	}
	log.Printf("brew_outdated: current user: %s", currentUser.Username)

	// Execute 'brew outdated --verbose' command to get version information
	// Fun fact - TTY detection... need to use --verbose when running programatically.
	// Run as the Homebrew owner to avoid "Running Homebrew as root" error
	var cmd *exec.Cmd
	var env []string

	if currentUser.Username == brewOwner {
		// Already running as the correct user, no need for sudo
		log.Printf("brew_outdated: already running as %s, no sudo needed", brewOwner)
		cmd = exec.CommandContext(ctx, brewPath, "outdated", "--verbose")
		env = os.Environ()
	} else {
		// Need to run as the Homebrew owner using sudo
		// Get the home directory of the brew owner for proper environment setup
		brewOwnerUser, err := user.Lookup(brewOwner)
		if err != nil {
			log.Printf("brew_outdated: could not lookup user %s: %v", brewOwner, err)
			return results, nil
		}

		log.Printf("brew_outdated: running as %s via sudo (current: %s)", brewOwner, currentUser.Username)
		// When running as root (Fleet), sudo -u works without a password
		// No need for -n flag or special configuration
		cmd = exec.CommandContext(ctx, "sudo", "-u", brewOwner, brewPath, "outdated", "--verbose")

		// Set environment with Homebrew owner's HOME and proper PATH
		env = append(os.Environ(),
			"HOME="+brewOwnerUser.HomeDir,
			"USER="+brewOwner,
		)
		log.Printf("brew_outdated: using HOME=%s, USER=%s", brewOwnerUser.HomeDir, brewOwner)
	}

	// Set environment to avoid auto-updates and analytics, and ensure PATH includes Homebrew paths
	cmd.Env = append(env,
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
		"PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:"+os.Getenv("PATH"))

	// Use CombinedOutput to capture both stdout and stderr for better error handling
	log.Printf("brew_outdated: executing brew outdated command")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		log.Printf("brew_outdated: command exited with error: %v, output length: %d", err, len(outputStr))
		// brew outdated returns non-zero exit code if there are no outdated packages
		// Check if the output contains actual error messages (not just empty)

		// If output is empty or only contains whitespace, assume no outdated packages
		if strings.TrimSpace(outputStr) == "" {
			log.Printf("brew_outdated: empty output, assuming no outdated packages")
			return results, nil
		}

		// Check if this looks like an actual error (contains "Error:" or similar)
		if strings.Contains(outputStr, "Error:") || strings.Contains(outputStr, "error:") {
			// Check for the specific "Running Homebrew as root" error
			if strings.Contains(outputStr, "Running Homebrew as root") {
				// Log for debugging (Fleet logs may be available)
				log.Printf("brew_outdated: Homebrew refused to run as root")
				return results, nil
			}
			// Check for sudo password prompt or permission denied
			if strings.Contains(outputStr, "password") || strings.Contains(outputStr, "sudo:") ||
				strings.Contains(outputStr, "a password is required") {
				// Log for debugging - this is likely the issue in Fleet
				log.Printf("brew_outdated: sudo authentication required (output: %s)", strings.TrimSpace(outputStr))
				return results, nil
			}
			// Log other errors for debugging
			log.Printf("brew_outdated: brew command error: %s", strings.TrimSpace(outputStr))
			return results, nil
		}

		// Otherwise, try to parse the output anyway (brew might exit non-zero but still have data)
		log.Printf("brew_outdated: attempting to parse output despite error")
	}

	// Parse the output
	log.Printf("brew_outdated: parsing output, length: %d", len(outputStr))
	// Format can be one of:
	// 1. "package_name (installed_version) < latest_version" - for updates
	// 2. "package_name (installed_version) != latest_version" - for cask version changes
	// Example: "aom (3.12.0) < 3.13.1"
	// Example: "displaylink (14.2,2025-11) != 15.0,2025-12"
	// Also handles multiple installed versions: "certbot (2.11.0_2, 3.2.0) < 5.2.2_1"

	lines := strings.Split(string(output), "\n")

	// Regex to match the outdated package format - handles both < and != operators
	// Captures: package name, installed version(s), operator, latest version
	outdatedRegex := regexp.MustCompile(`^([^\s]+)\s+\(([^)]+)\)\s+(<|!=)\s+(.+)$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip progress/status lines (like "✔︎ JSON API..." or lines with "Downloaded")
		if strings.Contains(line, "Downloaded") || strings.Contains(line, "API") ||
			strings.HasPrefix(line, "✔") || strings.HasPrefix(line, "==>") {
			continue
		}

		matches := outdatedRegex.FindStringSubmatch(line)
		if len(matches) != 5 {
			// Skip lines that don't match the expected format
			continue
		}

		packageName := matches[1]
		installedVersions := matches[2]
		// matches[3] is the operator (< or !=)
		latestVersion := strings.TrimSpace(matches[4])

		// Handle multiple installed versions (comma-separated)
		// We'll create one row per installed version
		versionList := strings.Split(installedVersions, ",")

		for _, version := range versionList {
			version = strings.TrimSpace(version)

			results = append(results, map[string]string{
				"name":              packageName,
				"installed_version": version,
				"latest_version":    latestVersion,
			})
		}
	}

	log.Printf("brew_outdated: parsed %d outdated packages", len(results))
	return results, nil
}

// findBrewBinary finds the brew binary path
func findBrewBinary() (string, error) {
	// First, try to find brew using 'which' command
	whichCmd := exec.Command("which", "brew")
	output, err := whichCmd.Output()
	if err == nil {
		brewPath := strings.TrimSpace(string(output))
		if brewPath != "" {
			return brewPath, nil
		}
	}

	// Fallback: check common Homebrew installation paths
	homebrewPaths := []string{
		"/opt/homebrew/bin/brew",              // Apple Silicon Mac
		"/usr/local/bin/brew",                 // Intel Mac
		"/home/linuxbrew/.linuxbrew/bin/brew", // Linux
	}

	for _, path := range homebrewPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("brew binary not found")
}

// findHomebrewOwner finds the user who owns the Homebrew installation
// This is needed because Homebrew refuses to run as root
// This follows osquery best practices: determine the owner of the tool and run as that user
func findHomebrewOwner(brewPath string) (string, error) {
	// Determine Homebrew root directory from brew binary path
	// e.g., /opt/homebrew/bin/brew -> /opt/homebrew
	// e.g., /usr/local/bin/brew -> /usr/local
	brewRoot := filepath.Dir(filepath.Dir(brewPath))

	// Check if the directory exists
	info, err := os.Stat(brewRoot)
	if err != nil {
		return "", fmt.Errorf("could not stat Homebrew root %s: %v", brewRoot, err)
	}

	// Get the owner's UID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("could not get file stat info")
	}

	// Look up the username from UID
	owner, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
	if err != nil {
		return "", fmt.Errorf("could not lookup user ID %d: %v", stat.Uid, err)
	}

	return owner.Username, nil
}
