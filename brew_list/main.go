package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
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
	// Find Homebrew installation path
	brewPath, err := findHomebrewPath()
	if err != nil {
		return nil, fmt.Errorf("could not find Homebrew installation: %v", err)
	}

	log.Printf("Found Homebrew at: %s", brewPath)

	// Read from Homebrew database directly
	results, err := readHomebrewDatabase(brewPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Homebrew database: %v", err)
	}

	return results, nil
}

func findHomebrewPath() (string, error) {
	// First, try to find brew using 'which' command
	whichCmd := exec.Command("which", "brew")
	output, err := whichCmd.Output()
	if err == nil {
		brewPath := strings.TrimSpace(string(output))
		if brewPath != "" {
			// Extract the Homebrew root directory from the brew binary path
			// e.g., /opt/homebrew/bin/brew -> /opt/homebrew
			homebrewRoot := filepath.Dir(filepath.Dir(brewPath))
			if _, err := os.Stat(homebrewRoot); err == nil {
				return homebrewRoot, nil
			}
		}
	}

	// Fallback: check common Homebrew installation paths
	homebrewPaths := []string{
		"/opt/homebrew",              // Apple Silicon Mac
		"/usr/local",                 // Intel Mac
		"/home/linuxbrew/.linuxbrew", // Linux
	}

	for _, path := range homebrewPaths {
		// Check if the path exists and contains Homebrew
		if _, err := os.Stat(path); err == nil {
			// Check for Homebrew-specific files
			if _, err := os.Stat(filepath.Join(path, "bin", "brew")); err == nil {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("Homebrew installation not found")
}

func readHomebrewDatabase(brewPath string) ([]map[string]string, error) {
	log.Printf("Looking for Homebrew database in: %s", brewPath)

	// Check what's actually in the var/db directory
	varDBPath := filepath.Join(brewPath, "var", "db")
	if entries, err := os.ReadDir(varDBPath); err == nil {
		log.Printf("Contents of %s:", varDBPath)
		for _, entry := range entries {
			log.Printf("  - %s", entry.Name())
		}
	} else {
		log.Printf("Could not read directory %s: %v", varDBPath, err)
	}

	// Try multiple possible database locations
	possibleDBPaths := []string{
		filepath.Join(brewPath, "var", "db", "formula_versions.db"),
		filepath.Join(brewPath, "var", "db", "formula_versions.sqlite"),
		filepath.Join(brewPath, "var", "db", "formula_versions"),
		filepath.Join(brewPath, "var", "db", "homebrew.db"),
		filepath.Join(brewPath, "var", "db", "homebrew.sqlite"),
		filepath.Join(brewPath, "var", "db", "homebrew"),
	}

	var dbPath string
	for _, path := range possibleDBPaths {
		if _, err := os.Stat(path); err == nil {
			dbPath = path
			log.Printf("Found database at: %s", dbPath)
			break
		}
	}

	if dbPath == "" {
		log.Printf("No database found, falling back to brew commands")
		return readBrewCommands(brewPath)
	}

	// Copy database to temporary location to avoid locking issues
	tempDB, err := copyDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to copy database: %v", err)
	}
	defer os.Remove(tempDB)

	// Open the temporary database
	db, err := sql.Open("sqlite3", tempDB)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	// Query the database for installed packages
	rows, err := db.Query(`
		SELECT name, version, path 
		FROM formula_versions 
		WHERE installed = 1
		ORDER BY name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query database: %v", err)
	}
	defer rows.Close()

	var results []map[string]string
	for rows.Next() {
		var name, version, path sql.NullString
		err := rows.Scan(&name, &version, &path)
		if err != nil {
			log.Printf("Warning: failed to scan row: %v", err)
			continue
		}

		packageName := ""
		if name.Valid {
			packageName = name.String
		}

		packageVersion := ""
		if version.Valid {
			packageVersion = version.String
		}

		installPath := ""
		if path.Valid {
			installPath = path.String
		} else {
			// Fallback: construct path from Homebrew prefix
			installPath = filepath.Join(brewPath, "opt", packageName)
		}

		if packageName != "" {
			results = append(results, map[string]string{
				"package_name": packageName,
				"version":      packageVersion,
				"install_path": installPath,
			})
		}
	}

	return results, nil
}

func copyDatabase(srcPath string) (string, error) {
	// Create temporary file
	tempFile, err := os.CreateTemp("", "homebrew_db_*.db")
	if err != nil {
		return "", err
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	// Copy the database file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		os.Remove(tempPath)
		return "", err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(tempPath)
	if err != nil {
		os.Remove(tempPath)
		return "", err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		os.Remove(tempPath)
		return "", err
	}

	return tempPath, nil
}

func readBrewCommands(brewPath string) ([]map[string]string, error) {
	// Use brew commands with proper environment setup to avoid root issues
	brewBinary := filepath.Join(brewPath, "bin", "brew")

	// Get list of installed packages
	cmd := exec.Command(brewBinary, "list")
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("brew list command failed: %v", err)
	}

	// Try to get versions using brew list --versions first
	versionMap := make(map[string]string)
	versionCmd := exec.Command(brewBinary, "list", "--versions")
	versionCmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1")
	versionOutput, err := versionCmd.CombinedOutput()
	if err != nil {
		log.Printf("brew list --versions failed: %v, output: %s", err, string(versionOutput))
		// Fallback: try to get versions from package directories
		versionMap = getVersionsFromDirectories(brewPath, strings.Fields(string(output)))
	} else {
		// Parse versions from command output
		scanner := bufio.NewScanner(strings.NewReader(string(versionOutput)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				versionMap[parts[0]] = parts[1]
			}
		}
	}

	// Parse package list and build results
	results := []map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		packageName := strings.TrimSpace(scanner.Text())
		if packageName == "" {
			continue
		}

		// Get version from the map and construct install path
		version := versionMap[packageName]
		installPath := filepath.Join(brewPath, "opt", packageName)

		results = append(results, map[string]string{
			"package_name": packageName,
			"version":      version,
			"install_path": installPath,
		})
	}

	return results, nil
}

func getVersionsFromDirectories(brewPath string, packageNames []string) map[string]string {
	versionMap := make(map[string]string)

	for _, packageName := range packageNames {
		// Try to read version from package directory
		packagePath := filepath.Join(brewPath, "opt", packageName)

		// Check if there's a version file
		versionFile := filepath.Join(packagePath, "VERSION")
		if content, err := os.ReadFile(versionFile); err == nil {
			version := strings.TrimSpace(string(content))
			if version != "" {
				versionMap[packageName] = version
				continue
			}
		}

		// Check if there's a .version file
		versionFile = filepath.Join(packagePath, ".version")
		if content, err := os.ReadFile(versionFile); err == nil {
			version := strings.TrimSpace(string(content))
			if version != "" {
				versionMap[packageName] = version
				continue
			}
		}

		// Try to extract version from symlink target
		if linkTarget, err := os.Readlink(packagePath); err == nil {
			// Extract version from path like /opt/homebrew/Cellar/package/1.2.3
			parts := strings.Split(linkTarget, "/")
			for i, part := range parts {
				if part == "Cellar" && i+2 < len(parts) {
					// The version should be the part after the package name
					versionMap[packageName] = parts[i+2]
					break
				}
			}
		}
	}

	return versionMap
}
