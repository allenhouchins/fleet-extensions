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
		// Silently return empty results if brew is not found
		return results, nil
	}

	// Find Homebrew owner to run command as non-root user
	brewOwner, err := findHomebrewOwner(brewPath)
	if err != nil {
		return results, nil
	}

	// Check if we're already running as the brew owner
	currentUser, err := user.Current()
	if err != nil {
		return results, nil
	}

	// Execute 'brew outdated --verbose' command to get version information
	var cmd *exec.Cmd
	var env []string

	if currentUser.Username == brewOwner {
		// Already running as brew owner, no sudo needed
		cmd = exec.Command(brewPath, "outdated", "--verbose")
		env = os.Environ()
	} else {
		// Not running as brew owner, check if sudo is available
		sudoPath, err := exec.LookPath("sudo")
		if err != nil {
			// sudo not found, try running brew directly with owner's environment
			brewOwnerUser, err := user.Lookup(brewOwner)
			if err != nil {
				return results, nil
			}

			cmd = exec.Command(brewPath, "outdated", "--verbose")
			env = append(os.Environ(),
				"HOME="+brewOwnerUser.HomeDir,
				"USER="+brewOwner,
			)
		} else {
			// sudo is available, use it to run as brew owner
			brewOwnerUser, err := user.Lookup(brewOwner)
			if err != nil {
				return results, nil
			}

			cmd = exec.Command(sudoPath, "-u", brewOwner, brewPath, "outdated", "--verbose")
			env = append(os.Environ(),
				"HOME="+brewOwnerUser.HomeDir,
				"USER="+brewOwner,
			)
		}
	}

	// Set environment to avoid auto-updates and analytics
	cmd.Env = append(env,
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
		"PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:"+os.Getenv("PATH"))

	// Use CombinedOutput to capture both stdout and stderr
	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		// If output is empty or only contains whitespace, assume no outdated packages
		if strings.TrimSpace(outputStr) == "" {
			return results, nil
		}

		// Check if this looks like an actual error
		if strings.Contains(outputStr, "Error:") || strings.Contains(outputStr, "error:") {
			// Silently handle common brew errors
			if strings.Contains(outputStr, "Running Homebrew as root") ||
				strings.Contains(outputStr, "password") ||
				strings.Contains(outputStr, "sudo:") ||
				strings.Contains(outputStr, "a password is required") {
				return results, nil
			}
			// For other errors, return empty results gracefully
			return results, nil
		}
	}

	// Parse the output
	lines := strings.Split(string(output), "\n")

	// Regex to match the outdated package format - handles both < and != operators
	// Format: "package_name (installed_version) < latest_version"
	// Example: "aom (3.12.0) < 3.13.1"
	// Example: "displaylink (14.2,2025-11) != 15.0,2025-12"
	outdatedRegex := regexp.MustCompile(`^([^\s]+)\s+\(([^)]+)\)\s+(<|!=)\s+(.+)$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip progress/status lines
		if strings.Contains(line, "Downloaded") || strings.Contains(line, "API") ||
			strings.HasPrefix(line, "✔") || strings.HasPrefix(line, "==>") {
			continue
		}

		matches := outdatedRegex.FindStringSubmatch(line)
		if len(matches) != 5 {
			continue
		}

		packageName := matches[1]
		installedVersions := matches[2]
		// matches[3] is the operator (< or !=)
		latestVersion := strings.TrimSpace(matches[4])

		// Handle multiple installed versions (comma-separated)
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

// findHomebrewOwner determines who owns the Homebrew installation
func findHomebrewOwner(brewPath string) (string, error) {
	// Get the Homebrew root directory (e.g., /opt/homebrew or /usr/local)
	homebrewRoot := filepath.Dir(filepath.Dir(brewPath))

	// Get the file info to determine the owner
	fileInfo, err := os.Stat(homebrewRoot)
	if err != nil {
		return "", fmt.Errorf("failed to stat homebrew root: %v", err)
	}

	// Get the UID from the file info (requires sys package on Unix systems)
	stat, ok := fileInfo.Sys().(interface{ Uid() uint32 })
	if !ok {
		return "", fmt.Errorf("unable to get owner UID from file info")
	}

	uid := stat.Uid()

	// Look up the username from the UID
	u, err := user.LookupId(fmt.Sprintf("%d", uid))
	if err != nil {
		return "", fmt.Errorf("failed to lookup user by UID %d: %v", uid, err)
	}

	return u.Username, nil
}
