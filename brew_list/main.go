package main

import (
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

	// Read from Homebrew database directly
	results, err := readHomebrewDatabase(brewPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Homebrew database: %v", err)
	}

	return results, nil
}

func findHomebrewPath() (string, error) {
	// Check common Homebrew installation paths
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
	// Homebrew stores package information in a SQLite database
	dbPath := filepath.Join(brewPath, "var", "db", "formula_versions.db")

	// Check if database exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Try alternative database location
		dbPath = filepath.Join(brewPath, "var", "db", "formula_versions.sqlite")
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("Homebrew database not found at %s", dbPath)
		}
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
