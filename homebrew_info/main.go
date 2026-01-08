package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

// Homebrew prefixes to check
var homebrewPrefixes = []string{
	"/usr/local",
	"/opt/homebrew",
}

// Cache for latest versions to avoid repeated brew info calls
type versionCache struct {
	mu        sync.RWMutex
	versions  map[string]string
	timestamp time.Time
	ttl       time.Duration
}

var latestVersionCache = &versionCache{
	versions: make(map[string]string),
	ttl:      time.Hour, // Cache for 1 hour
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
		"homebrew_info",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"homebrew_info",
		homebrewPackagesColumns(),
		generateHomebrewPackages,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func homebrewPackagesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("path"),
		table.TextColumn("version"),
		table.TextColumn("type"),
		table.TextColumn("auto_updates"),
		table.TextColumn("app_name"),
		table.TextColumn("latest_version"),
		table.TextColumn("is_latest"),
	}
}

func generateHomebrewPackages(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	// Use default prefixes (prefix column removed, but we still need to check prefixes internally)
	var prefixesToCheck []string = homebrewPrefixes
	userRequested := false

	// Process each prefix
	for _, prefix := range prefixesToCheck {
		prefixResults, err := packagesFromPrefix(prefix, userRequested)
		if err != nil {
			// Log error but continue with other prefixes
			log.Printf("Error processing prefix %s: %v", prefix, err)
			continue
		}
		results = append(results, prefixResults...)
	}

	return results, nil
}

func packagesFromPrefix(prefix string, userRequested bool) ([]map[string]string, error) {
	var results []map[string]string

	// Check if prefix exists
	if _, err := os.Stat(prefix); err != nil {
		// Only log warning if user explicitly requested this prefix
		// This avoids noise when checking default prefixes that don't exist
		return results, nil
	}

	// Process formulas
	formulaResults, err := computeVersionsForFormulas(prefix, userRequested)
	if err != nil {
		if userRequested {
			log.Printf("Warning: Error processing formulas for prefix %s: %v", prefix, err)
		}
	} else {
		results = append(results, formulaResults...)
	}

	// Process casks
	caskResults, err := computeVersionsForCasks(prefix, userRequested)
	if err != nil {
		if userRequested {
			log.Printf("Warning: Error processing casks for prefix %s: %v", prefix, err)
		}
	} else {
		results = append(results, caskResults...)
	}

	return results, nil
}

func computeVersionsForFormulas(prefix string, userRequested bool) ([]map[string]string, error) {
	var results []map[string]string
	formulaDirPath := filepath.Join(prefix, "Cellar")
	packageType := "formula"

	if _, err := os.Stat(formulaDirPath); err != nil {
		// Only log warning if user explicitly requested this prefix
		// This avoids noise when checking default prefixes that don't exist
		return results, nil
	}

	// Get canonical path
	canonicalPath, err := filepath.EvalSymlinks(formulaDirPath)
	if err != nil {
		canonicalPath = formulaDirPath
	}

	// List directories in Cellar (each directory is a formula)
	entries, err := os.ReadDir(canonicalPath)
	if err != nil {
		if userRequested {
			log.Printf("Warning: Error listing %s: %v", canonicalPath, err)
		}
		return results, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		formulaPath := filepath.Join(canonicalPath, entry.Name())
		formulaName := entry.Name()

		// Get versions for this formula
		versions, err := getHomebrewVersionsFromPath(formulaPath)
		if err != nil {
			continue
		}

		// Get latest version once per package (not per installed version)
		latestVersion := getLatestVersionFromBrew(formulaName, packageType)

		for _, version := range versions {
			// Determine if this version is the latest
			isLatest := "no"
			if latestVersion != "" && version == latestVersion {
				isLatest = "yes"
			}

			results = append(results, map[string]string{
				"name":           formulaName,
				"path":           formulaPath,
				"version":        version,
				"type":           packageType,
				"auto_updates":   "",
				"app_name":       "",
				"latest_version": latestVersion,
				"is_latest":      isLatest,
			})
		}
	}

	return results, nil
}

func computeVersionsForCasks(prefix string, userRequested bool) ([]map[string]string, error) {
	var results []map[string]string
	caskDirPath := filepath.Join(prefix, "Caskroom")
	packageType := "cask"

	if _, err := os.Stat(caskDirPath); err != nil {
		// Only log warning if user explicitly requested this prefix
		// This avoids noise when checking default prefixes that don't exist
		return results, nil
	}

	// Get canonical path
	canonicalPath, err := filepath.EvalSymlinks(caskDirPath)
	if err != nil {
		canonicalPath = caskDirPath
	}

	// List directories in Caskroom (each directory is a cask)
	entries, err := os.ReadDir(canonicalPath)
	if err != nil {
		if userRequested {
			log.Printf("Warning: Error listing %s: %v", canonicalPath, err)
		}
		return results, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		caskPath := filepath.Join(canonicalPath, entry.Name())
		caskName := entry.Name()

		// Get versions for this cask
		versions, err := getHomebrewVersionsFromPath(caskPath)
		if err != nil {
			continue
		}

		// Get auto_updates and app_name from metadata
		autoUpdates := getHomebrewAutoUpdate(caskPath)
		appName := getInstalledAppNameFromMetadata(caskPath)

		// Get latest version once per package (not per installed version)
		latestVersion := getLatestVersionFromBrew(caskName, packageType)

		for _, version := range versions {
			autoUpdatesStr := "0"
			if autoUpdates {
				autoUpdatesStr = "1"
			}

			// Determine if this version is the latest
			isLatest := "no"
			if latestVersion != "" && version == latestVersion {
				isLatest = "yes"
			}

			results = append(results, map[string]string{
				"name":           caskName,
				"path":           caskPath,
				"version":        version,
				"type":           packageType,
				"auto_updates":   autoUpdatesStr,
				"app_name":       appName,
				"latest_version": latestVersion,
				"is_latest":      isLatest,
			})
		}
	}

	return results, nil
}

// getLatestVersionFromBrew gets the latest available version of a package from Homebrew
// Uses brew info --json=v2 and caches results for performance
func getLatestVersionFromBrew(packageName, packageType string) string {
	// Check cache first
	cacheKey := packageType + ":" + packageName

	latestVersionCache.mu.RLock()
	now := time.Now()
	if latestVersionCache.timestamp.Add(latestVersionCache.ttl).After(now) {
		if version, ok := latestVersionCache.versions[cacheKey]; ok {
			latestVersionCache.mu.RUnlock()
			return version
		}
	} else {
		// Cache expired, clear it
		latestVersionCache.versions = make(map[string]string)
		latestVersionCache.timestamp = now
	}
	latestVersionCache.mu.RUnlock()

	// Find brew binary
	brewPath, err := findBrewBinary()
	if err != nil {
		log.Printf("Error finding brew binary: %v", err)
		// Cache empty to avoid retries
		latestVersionCache.mu.Lock()
		latestVersionCache.versions[cacheKey] = ""
		latestVersionCache.mu.Unlock()
		return ""
	}

	// Build brew command - prefer JSON output for more reliable parsing
	var cmd *exec.Cmd
	if packageType == "cask" {
		cmd = exec.Command(brewPath, "info", "--cask", "--json=v2", packageName)
	} else {
		cmd = exec.Command(brewPath, "info", "--json=v2", packageName)
	}

	// Set environment to avoid auto-updates and analytics
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")

	// Capture stderr separately to avoid polluting output
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		log.Printf("Error executing brew info for %s: %v", packageName, err)
		// Cache empty to avoid retries
		latestVersionCache.mu.Lock()
		latestVersionCache.versions[cacheKey] = ""
		latestVersionCache.mu.Unlock()
		return ""
	}

	latestVersion := ""

	// Try parsing JSON first (more reliable)
	// JSON structure: {"formulae": [...]} or {"casks": [...]}
	var brewInfo map[string]interface{}
	if err := json.Unmarshal(output, &brewInfo); err == nil {
		// Handle formulas
		if formulae, ok := brewInfo["formulae"].([]interface{}); ok && len(formulae) > 0 {
			if item, ok := formulae[0].(map[string]interface{}); ok {
				if versions, ok := item["versions"].(map[string]interface{}); ok {
					if stable, ok := versions["stable"].(string); ok && stable != "" {
						latestVersion = stable
					}
				}
			}
		}
		// Handle casks
		if casks, ok := brewInfo["casks"].([]interface{}); ok && len(casks) > 0 {
			if item, ok := casks[0].(map[string]interface{}); ok {
				// For casks, version is at the top level
				if version, ok := item["version"].(string); ok && version != "" {
					latestVersion = version
				}
			}
		}
	}

	// If JSON parsing failed or didn't find version, try text parsing as fallback
	if latestVersion == "" {
		// Fallback: Parse text output
		// Example output formats:
		// "wget: stable 1.21.4 (bottled), HEAD"
		// "wget: 1.21.3 (installed), 1.21.4 (latest)"
		outputStr := string(output)

		// Try pattern: "version (latest)"
		latestRegex := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)*(?:[a-z0-9]+)?)\s*\(latest\)`)
		matches := latestRegex.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			latestVersion = matches[1]
		} else {
			// Try pattern: "stable version" (for formulas) - be more specific to avoid false matches
			// Match "stable" followed by a version number pattern
			stableRegex := regexp.MustCompile(`stable\s+(\d+\.\d+(?:\.\d+)*(?:[a-z0-9]+)?)`)
			matches = stableRegex.FindStringSubmatch(outputStr)
			if len(matches) > 1 {
				latestVersion = matches[1]
			}
		}
	}

	// Cache the result (even if empty)
	latestVersionCache.mu.Lock()
	latestVersionCache.versions[cacheKey] = latestVersion
	latestVersionCache.mu.Unlock()

	return latestVersion
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

func getHomebrewVersionsFromPath(path string) ([]string, error) {
	var versions []string

	entries, err := os.ReadDir(path)
	if err != nil {
		return versions, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		version := entry.Name()
		// Skip .metadata directory
		if version == ".metadata" {
			continue
		}

		versions = append(versions, version)
	}

	return versions, nil
}

func getMetadataFileForCask(path string) string {
	// Metadata files are typically in:
	// /opt/homebrew/Caskroom/iterm2/.metadata/3.5.9/20241116155943.669/Casks/iterm2.json
	// or
	// /opt/homebrew/Caskroom/vlc/.metadata/3.0.18/20230607170348.510/Casks/vlc.rb

	appName := filepath.Base(path)
	metadataPath := filepath.Join(path, ".metadata")

	if _, err := os.Stat(metadataPath); err != nil {
		return ""
	}

	// Recursively search for .json or .rb files with the app name
	var metadataFile string
	err := filepath.Walk(metadataPath, func(walkPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue on error
		}

		if info.IsDir() {
			return nil
		}

		filename := filepath.Base(walkPath)
		if filename == appName+".json" || filename == appName+".rb" {
			metadataFile = walkPath
			return filepath.SkipAll // Found it, stop walking
		}

		return nil
	})

	if err != nil {
		return ""
	}

	return metadataFile
}

func getHomebrewAutoUpdate(path string) bool {
	metadataFile := getMetadataFileForCask(path)
	if metadataFile == "" {
		return false
	}

	if strings.HasSuffix(metadataFile, ".json") {
		return getBooleanValueFromJsonFile(metadataFile, "auto_updates")
	}

	if strings.HasSuffix(metadataFile, ".rb") {
		return checkAutoUpdatesInRubyFile(metadataFile)
	}

	return false
}

func getInstalledAppNameFromMetadata(path string) string {
	metadataFile := getMetadataFileForCask(path)
	if metadataFile == "" {
		return ""
	}

	if strings.HasSuffix(metadataFile, ".json") {
		return getAppNameFromJsonManifest(metadataFile)
	}

	if strings.HasSuffix(metadataFile, ".rb") {
		return getAppNameFromRubyManifest(metadataFile)
	}

	return ""
}

func checkAutoUpdatesInRubyFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Regex to match "auto_updates true" line
	autoUpdatesRegex := regexp.MustCompile(`^\s*auto_updates\s*true\s*$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if autoUpdatesRegex.MatchString(line) {
			return true
		}
	}

	return false
}

func getBooleanValueFromJsonFile(filePath string, key string) bool {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return false
	}

	if value, ok := data[key]; ok {
		if boolValue, ok := value.(bool); ok {
			return boolValue
		}
	}

	return false
}

func getAppNameFromJsonManifest(filePath string) string {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal(content, &data); err != nil {
		return ""
	}

	// Look for artifacts array
	artifacts, ok := data["artifacts"].([]interface{})
	if !ok {
		return ""
	}

	// Iterate through artifacts to find one with "app" key
	for _, artifact := range artifacts {
		artifactMap, ok := artifact.(map[string]interface{})
		if !ok {
			continue
		}

		app, ok := artifactMap["app"]
		if !ok {
			continue
		}

		// app can be a string or an array of strings
		if appStr, ok := app.(string); ok {
			return appStr
		}

		if appArray, ok := app.([]interface{}); ok && len(appArray) > 0 {
			if appStr, ok := appArray[0].(string); ok {
				return appStr
			}
		}
	}

	return ""
}

func getAppNameFromRubyManifest(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Regex to match "app 'App.app'" or app "App.app"
	appRegex := regexp.MustCompile(`^\s*app\s*["'](.*\.app)["']\s*$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := appRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}
