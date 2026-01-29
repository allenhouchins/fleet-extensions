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

	// DEBUG: Log current context
	log.Printf("=== DEBUG: Starting generateBrewOutdated ===")
	currentUser, err := user.Current()
	if err != nil {
		log.Printf("DEBUG: Failed to get current user: %v", err)
	} else {
		log.Printf("DEBUG: Running as user: %s (UID: %s)", currentUser.Username, currentUser.Uid)
	}
	log.Printf("DEBUG: PATH=%s", os.Getenv("PATH"))
	log.Printf("DEBUG: HOME=%s", os.Getenv("HOME"))
	log.Printf("DEBUG: USER=%s", os.Getenv("USER"))

	// Find brew binary
	brewPath, err := findBrewBinary()
	if err != nil {
		log.Printf("DEBUG: Error finding brew binary: %v", err)
		return results, nil
	}
	log.Printf("DEBUG: Found brew at: %s", brewPath)

	// Find Homebrew owner to run command as non-root user
	brewOwner, err := findHomebrewOwner(brewPath)
	if err != nil {
		log.Printf("DEBUG: Error finding homebrew owner: %v", err)
		return results, nil
	}
	log.Printf("DEBUG: Homebrew owner: %s", brewOwner)

	// Check if we're already running as the brew owner
	currentUser, err = user.Current()
	if err != nil {
		log.Printf("DEBUG: Error getting current user: %v", err)
		return results, nil
	}
	log.Printf("DEBUG: Current user: %s", currentUser.Username)

	// Execute 'brew outdated --verbose' command to get version information
	var cmd *exec.Cmd
	var env []string

	if currentUser.Username == brewOwner {
		log.Printf("DEBUG: Already running as brew owner, no sudo needed")
		cmd = exec.Command(brewPath, "outdated", "--verbose")
		env = os.Environ()
	} else {
		log.Printf("DEBUG: Not running as brew owner, attempting sudo -u %s", brewOwner)
		// Get the home directory of the brew owner for proper environment setup
		brewOwnerUser, err := user.Lookup(brewOwner)
		if err != nil {
			log.Printf("DEBUG: Error looking up brew owner user: %v", err)
			return results, nil
		}
		log.Printf("DEBUG: Brew owner home directory: %s", brewOwnerUser.HomeDir)

		cmd = exec.Command("sudo", "-u", brewOwner, brewPath, "outdated", "--verbose")

		env = append(os.Environ(),
			"HOME="+brewOwnerUser.HomeDir,
			"USER="+brewOwner,
		)
	}

	// Set environment to avoid auto-updates and analytics, and ensure PATH includes Homebrew paths
	cmd.Env = append(env,
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
		"PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:"+os.Getenv("PATH"))

	// DEBUG: Log the command being executed
	log.Printf("DEBUG: Command: %v", cmd.Args)
	log.Printf("DEBUG: Command Env (selected): HOME=%s, USER=%s, HOMEBREW_NO_AUTO_UPDATE=%s, HOMEBREW_NO_ANALYTICS=%s",
		cmd.Env[0], cmd.Env[1], cmd.Env[2], cmd.Env[3])

	// Use CombinedOutput to capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	log.Printf("DEBUG: Command exit code: %v", err)
	log.Printf("DEBUG: Command output length: %d bytes", len(output))
	log.Printf("DEBUG: Command output:\n%s", string(output))

	if err != nil {
		log.Printf("DEBUG: Command failed with error: %v", err)
		outputStr := string(output)

		// If output is empty or only contains whitespace, assume no outdated packages
		if strings.TrimSpace(outputStr) == "" {
			log.Printf("DEBUG: Output is empty, assuming no outdated packages")
			return results, nil
		}

		// Check if this looks like an actual error (contains "Error:" or similar)
		if strings.Contains(outputStr, "Error:") || strings.Contains(outputStr, "error:") {
			log.Printf("DEBUG: Output contains error keywords")
			// Check for the specific "Running Homebrew as root" error
			if strings.Contains(outputStr, "Running Homebrew as root") {
				log.Printf("DEBUG: Detected 'Running Homebrew as root' error")
				return results, nil
			}
			// Check for sudo password prompt or permission denied
			if strings.Contains(outputStr, "password") || strings.Contains(outputStr, "sudo:") ||
				strings.Contains(outputStr, "a password is required") {
				log.Printf("DEBUG: Detected password/permission error")
				return results, nil
			}
			// For other errors, return empty results gracefully
			log.Printf("DEBUG: Other error detected, returning empty results")
			return results, nil
		}

		log.Printf("DEBUG: Output contains data despite non-zero exit code, attempting to parse anyway")
	}

	// Parse the output
	log.Printf("DEBUG: Parsing output...")
	lines := strings.Split(string(output), "\n")
	log.Printf("DEBUG: Total lines: %d", len(lines))

	// Regex to match the outdated package format - handles both < and != operators
	outdatedRegex := regexp.MustCompile(`^([^\s]+)\s+\(([^)]+)\)\s+(<|!=)\s+(.+)$`)

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip progress/status lines
		if strings.Contains(line, "Downloaded") || strings.Contains(line, "API") ||
			strings.HasPrefix(line, "✔") || strings.HasPrefix(line, "==>") {
			log.Printf("DEBUG: Skipping progress line %d: %s", i, line)
			continue
		}

		matches := outdatedRegex.FindStringSubmatch(line)
		if len(matches) != 5 {
			log.Printf("DEBUG: Line %d does not match regex: %s", i, line)
			continue
		}

		packageName := matches[1]
		installedVersions := matches[2]
		latestVersion := strings.TrimSpace(matches[4])

		log.Printf("DEBUG: Matched package - name: %s, installed: %s, latest: %s",
			packageName, installedVersions, latestVersion)

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

	log.Printf("DEBUG: Total results: %d", len(results))
	log.Printf("=== DEBUG: Finished generateBrewOutdated ===")
	return results, nil
}

// findBrewBinary finds the brew binary path
func findBrewBinary() (string, error) {
	log.Printf("DEBUG: findBrewBinary: Starting search")

	// First, try to find brew using 'which' command
	whichCmd := exec.Command("which", "brew")
	output, err := whichCmd.Output()
	if err == nil {
		brewPath := strings.TrimSpace(string(output))
		if brewPath != "" {
			log.Printf("DEBUG: findBrewBinary: Found via 'which': %s", brewPath)
			return brewPath, nil
		}
	}
	log.Printf("DEBUG: findBrewBinary: 'which brew' failed, trying fallback paths")

	// Fallback: check common Homebrew installation paths
	homebrewPaths := []string{
		"/opt/homebrew/bin/brew",              // Apple Silicon Mac
		"/usr/local/bin/brew",                 // Intel Mac
		"/home/linuxbrew/.linuxbrew/bin/brew", // Linux
	}

	for _, path := range homebrewPaths {
		log.Printf("DEBUG: findBrewBinary: Checking if %s exists", path)
		if _, err := os.Stat(path); err == nil {
			log.Printf("DEBUG: findBrewBinary: Found at: %s", path)
			return path, nil
		}
		log.Printf("DEBUG: findBrewBinary: %s does not exist: %v", path, err)
	}

	log.Printf("DEBUG: findBrewBinary: brew binary not found in any location")
	return "", fmt.Errorf("brew binary not found")
}

// findHomebrewOwner finds the user who owns the Homebrew installation
func findHomebrewOwner(brewPath string) (string, error) {
	log.Printf("DEBUG: findHomebrewOwner: Starting")

	// Determine Homebrew root directory from brew binary path
	brewRoot := filepath.Dir(filepath.Dir(brewPath))
	log.Printf("DEBUG: findHomebrewOwner: Homebrew root: %s", brewRoot)

	// Check if the directory exists
	info, err := os.Stat(brewRoot)
	if err != nil {
		log.Printf("DEBUG: findHomebrewOwner: Failed to stat %s: %v", brewRoot, err)
		return "", fmt.Errorf("could not stat Homebrew root %s: %v", brewRoot, err)
	}

	// Get the owner's UID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		log.Printf("DEBUG: findHomebrewOwner: Could not get file stat info")
		return "", fmt.Errorf("could not get file stat info")
	}

	log.Printf("DEBUG: findHomebrewOwner: Homebrew directory owner UID: %d", stat.Uid)

	// Look up the username from UID
	owner, err := user.LookupId(fmt.Sprintf("%d", stat.Uid))
	if err != nil {
		log.Printf("DEBUG: findHomebrewOwner: Failed to lookup UID %d: %v", stat.Uid, err)
		return "", fmt.Errorf("could not lookup user ID %d: %v", stat.Uid, err)
	}

	log.Printf("DEBUG: findHomebrewOwner: Homebrew owner: %s", owner.Username)
	return owner.Username, nil
}
