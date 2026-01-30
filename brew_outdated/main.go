package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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

// HomebrewFormulaAPIResponse represents the JSON response from formulae.brew.sh API
type HomebrewFormulaAPIResponse struct {
	Name     string `json:"name"`
	Versions struct {
		Stable string `json:"stable"`
		Devel  string `json:"devel"`
		Head   string `json:"head"`
	} `json:"versions"`
}

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
		table.TextColumn("type"),
	}
}

func generateBrewOutdated(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	log.Printf("=== DEBUG: Starting generateBrewOutdated ===")

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

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	// For each installed package, check if it's outdated
	for pkgName, pkgInfo := range installedPackages {
		latestVersion, err := getLatestVersion(httpClient, pkgName, pkgInfo.pkgType)
		if err != nil {
			log.Printf("DEBUG: Error getting latest version for %s: %v", pkgName, err)
			continue
		}

		if latestVersion == "" {
			log.Printf("DEBUG: Could not find latest version for %s", pkgName)
			continue
		}

		// Compare versions - if they're different, package is outdated
		if pkgInfo.installedVersion != latestVersion {
			log.Printf("DEBUG: Package %s is outdated: %s < %s", pkgName, pkgInfo.installedVersion, latestVersion)
			results = append(results, map[string]string{
				"name":              pkgName,
				"installed_version": pkgInfo.installedVersion,
				"latest_version":    latestVersion,
				"type":              pkgInfo.pkgType,
			})
		} else {
			log.Printf("DEBUG: Package %s is up to date: %s", pkgName, pkgInfo.installedVersion)
		}
	}

	log.Printf("DEBUG: Found %d outdated packages", len(results))
	log.Printf("=== DEBUG: Finished generateBrewOutdated ===")
	return results, nil
}

type PackageInfo struct {
	installedVersion string
	pkgType          string
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

func readInstalledPackages(brewRoot string) map[string]PackageInfo {
	installed := make(map[string]PackageInfo)

	// Read formulas from Cellar
	cellarPath := filepath.Join(brewRoot, "Cellar")
	if entries, err := os.ReadDir(cellarPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgName := entry.Name()
			// Get the version from the opt symlink
			version := getVersionFromSymlink(brewRoot, pkgName)
			if version != "" {
				installed[pkgName] = PackageInfo{
					installedVersion: version,
					pkgType:          "formula",
				}
				log.Printf("DEBUG: Found formula %s version %s", pkgName, version)
			}
		}
	} else {
		log.Printf("DEBUG: Error reading Cellar: %v", err)
	}

	// Read casks from Caskroom
	caskroomPath := filepath.Join(brewRoot, "Caskroom")
	if entries, err := os.ReadDir(caskroomPath); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pkgName := entry.Name()
			// Get the version from the opt symlink
			version := getVersionFromSymlink(brewRoot, pkgName)
			if version != "" {
				installed[pkgName] = PackageInfo{
					installedVersion: version,
					pkgType:          "cask",
				}
				log.Printf("DEBUG: Found cask %s version %s", pkgName, version)
			}
		}
	} else {
		log.Printf("DEBUG: Error reading Caskroom: %v", err)
	}

	return installed
}

func getVersionFromSymlink(brewRoot, pkgName string) string {
	optPath := filepath.Join(brewRoot, "opt", pkgName)
	target, err := os.Readlink(optPath)
	if err != nil {
		return ""
	}

	// Extract version from path like ../Cellar/webp/1.4.2 or ../Caskroom/webp/1.4.2
	parts := strings.Split(target, "/")
	if len(parts) > 0 {
		version := parts[len(parts)-1]
		return version
	}
	return ""
}

func getLatestVersion(client *http.Client, pkgName, pkgType string) (string, error) {
	// Query the Homebrew JSON API
	apiURL := fmt.Sprintf("https://formulae.brew.sh/api/%s/%s.json", pkgType, pkgName)
	log.Printf("DEBUG: Querying API: %s", apiURL)

	resp, err := client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("failed to query API: %v", err)
	}
	defer resp.Body.Close()

	// Check for 404 or other errors
	if resp.StatusCode == 404 {
		log.Printf("DEBUG: Package %s not found in API (404)", pkgName)
		return "", fmt.Errorf("package not found in API")
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var apiResp HomebrewFormulaAPIResponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		log.Printf("DEBUG: Failed to parse JSON for %s: %v", pkgName, err)
		return "", fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Return the stable version
	if apiResp.Versions.Stable != "" {
		log.Printf("DEBUG: Got version %s from API for %s", apiResp.Versions.Stable, pkgName)
		return apiResp.Versions.Stable, nil
	}

	return "", fmt.Errorf("no stable version found in API response")
}
