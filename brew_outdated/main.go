package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
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
		return results, fmt.Errorf("brew binary not found: %v", err)
	}

	// Execute 'brew outdated --verbose' command to get version information
	// Fun fact - TTY detection... need to use --verbose when running programatically. 
	cmd := exec.Command(brewPath, "outdated", "--verbose")
	
	// Set environment to avoid auto-updates and analytics
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")
	
	output, err := cmd.Output()
	if err != nil {
		// brew outdated returns non-zero exit code if there are no outdated packages
		// So we should still try to parse the output
		if len(output) == 0 {
			return results, nil
		}
	}

	// Parse the output
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
			// Only log if it looks like it should be a package line
			if strings.Contains(line, "(") && strings.Contains(line, ")") {
				log.Printf("Warning: Could not parse line: %s", line)
			}
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
