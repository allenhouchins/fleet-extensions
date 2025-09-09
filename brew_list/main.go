package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
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
		"brew_list",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"brew_list",
		brewListColumns(),
		generateBrewList,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func brewListColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("package_name"),
		table.TextColumn("version"),
		table.TextColumn("install_path"),
	}
}

func getBrewCommand(args ...string) *exec.Cmd {
	// First, try to find brew using 'which' command
	whichCmd := exec.Command("which", "brew")
	output, err := whichCmd.Output()
	if err == nil {
		brewPath := strings.TrimSpace(string(output))
		if brewPath != "" {
			cmd := exec.Command(brewPath, args...)
			// Set PATH to include common Homebrew paths
			cmd.Env = append(os.Environ(), "PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:"+os.Getenv("PATH"))
			return cmd
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
			cmd := exec.Command(path, args...)
			// Set PATH to include common Homebrew paths
			cmd.Env = append(os.Environ(), "PATH=/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:"+os.Getenv("PATH"))
			return cmd
		}
	}

	// Final fallback: try 'brew' in PATH
	return exec.Command("brew", args...)
}

func generateBrewList(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// Get list of installed packages
	cmd := getBrewCommand("list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("brew list command failed: %v", err)
	}

	// Get versions for all packages at once
	versionCmd := getBrewCommand("list", "--versions")
	versionOutput, err := versionCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("brew list --versions command failed: %v", err)
	}

	// Parse versions into a map
	versionMap := make(map[string]string)
	versionScanner := bufio.NewScanner(strings.NewReader(string(versionOutput)))
	for versionScanner.Scan() {
		line := strings.TrimSpace(versionScanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			versionMap[parts[0]] = parts[1]
		}
	}

	results := []map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		packageName := strings.TrimSpace(scanner.Text())
		if packageName == "" {
			continue
		}

		// Get version from the map and install path
		version := versionMap[packageName]
		installPath := getInstallPath(packageName)

		results = append(results, map[string]string{
			"package_name": packageName,
			"version":      version,
			"install_path": installPath,
		})
	}

	return results, nil
}

func getInstallPath(packageName string) string {
	// Get install path using brew --prefix
	pathCmd := getBrewCommand("--prefix", packageName)
	pathOutput, err := pathCmd.Output()
	installPath := ""
	if err == nil {
		installPath = strings.TrimSpace(string(pathOutput))
	}

	// If install path is empty, try using brew info to get more details
	if installPath == "" {
		infoCmd := getBrewCommand("info", packageName)
		infoOutput, err := infoCmd.Output()
		if err == nil {
			// Parse brew info output to find the install path
			scanner := bufio.NewScanner(strings.NewReader(string(infoOutput)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "Installed to:") {
					// Extract path from "Installed to: /path/to/package"
					parts := strings.Split(line, "Installed to:")
					if len(parts) > 1 {
						installPath = strings.TrimSpace(parts[1])
						break
					}
				}
			}
		}
	}

	return installPath
}
