package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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

	server, err := osquery.NewExtensionManagerServer(
		"brew_outdated",
		*socket,
		osquery.ServerTimeout(time.Second*time.Duration(*timeout)),
		osquery.ServerPingInterval(time.Second*time.Duration(*interval)),
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

	// Find Homebrew root
	brewRoot, err := findHomebrewRoot()
	if err != nil {
		log.Printf("Error finding Homebrew root: %v", err)
		return results, nil
	}

	log.Printf("DEBUG: Homebrew root: %s", brewRoot)

	// Get installed packages and their versions
	installedPackages := readInstalledPackages(brewRoot)
	log.Printf("DEBUG: Found %d installed packages", len(installedPackages))

	// Get latest available versions from formula files
	latestVersions := readLatestVersions(brewRoot)
	log.Printf("DEBUG: Found %d formulas with version info", len(latestVersions))

	// Compare and find outdated packages
	for pkgName, installedVersion := range installedPackages {
		latestVersion, ok := latestVersions[pkgName]
		if !ok {
			// Couldn't find latest version for this package, skip it
			continue
		}

		// Simple version comparison (you'd want better version comparison logic)
		if installedVersion != latestVersion {
			results = append(results, map[string]string{
				"name":              pkgName,
				"installed_version": installedVersion,
				"latest_version":    latestVersion,
			})
		}
	}

	log.Printf("DEBUG: Found %d outdated packages", len(results))
	return results, nil
}

func findHomebrewRoot() (string, error) {
	possibleRoots := []string{
		"/opt/homebrew",
		"/usr/local",
	}

	for _, root := range possibleRoots {
		if _, err := os.Stat(root); err == nil {
			if _, err := os.Stat(filepath.Join(root, "Cellar")); err == nil {
				return root, nil
			}
		}
	}

	return "", fmt.Errorf("Homebrew root not found")
}

func readInstalledPackages(brewRoot string) map[string]string {
	installed := make(map[string]string)

	// Read formulas from Cellar
	cellarPath := filepath.Join(brewRoot, "Cellar")
	if entries, err := os.ReadDir(cellarPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgName := entry.Name()
			// Get the latest installed version (usually the one in opt symlink)
			optPath := filepath.Join(brewRoot, "opt", pkgName)
			if target, err := os.Readlink(optPath); err == nil {
				// Extract version from path like /opt/homebrew/Cellar/package/1.2.3
				parts := strings.Split(target, "/")
				if len(parts) > 0 {
					version := parts[len(parts)-1]
					installed[pkgName] = version
					log.Printf("DEBUG: Found formula %s version %s", pkgName, version)
				}
			}
		}
	}

	// Read casks from Caskroom
	caskroomPath := filepath.Join(brewRoot, "Caskroom")
	if entries, err := os.ReadDir(caskroomPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgName := entry.Name()
			optPath := filepath.Join(brewRoot, "opt", pkgName)
			if target, err := os.Readlink(optPath); err == nil {
				parts := strings.Split(target, "/")
				if len(parts) > 0 {
					version := parts[len(parts)-1]
					installed[pkgName] = version
					log.Printf("DEBUG: Found cask %s version %s", pkgName, version)
				}
			}
		}
	}

	return installed
}

func readLatestVersions(brewRoot string) map[string]string {
	latest := make(map[string]string)

	// Read formula definitions to get latest versions
	formulasPath := filepath.Join(brewRoot, "Library", "Taps", "homebrew", "homebrew-core", "Formula")
	if entries, err := os.ReadDir(formulasPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".rb") {
				pkgName := strings.TrimSuffix(entry.Name(), ".rb")
				version := extractVersionFromFormula(filepath.Join(formulasPath, entry.Name()))
				if version != "" {
					latest[pkgName] = version
					log.Printf("DEBUG: Formula %s latest version %s", pkgName, version)
				}
			}
		}
	}

	// Read cask definitions
	casksPath := filepath.Join(brewRoot, "Library", "Taps", "homebrew", "homebrew-casks", "Casks")
	if entries, err := os.ReadDir(casksPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".rb") {
				pkgName := strings.TrimSuffix(entry.Name(), ".rb")
				version := extractVersionFromFormula(filepath.Join(casksPath, entry.Name()))
				if version != "" {
					latest[pkgName] = version
					log.Printf("DEBUG: Cask %s latest version %s", pkgName, version)
				}
			}
		}
	}

	return latest
}

func extractVersionFromFormula(filePath string) string {
	// Read the formula file and extract version
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	contentStr := string(content)

	// Look for version = "x.y.z" pattern
	lines := strings.Split(contentStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Match lines like: version "1.2.3"
		if strings.HasPrefix(line, "version") && strings.Contains(line, "\"") {
			// Simple extraction - find the quoted version
			start := strings.Index(line, "\"")
			end := strings.LastIndex(line, "\"")
			if start != -1 && end != -1 && start < end {
				return line[start+1 : end]
			}
		}
	}

	return ""
}
