package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strconv"
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
		"mise",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Register the tables
	server.RegisterPlugin(table.NewPlugin("mise_installs", miseInstallsColumns(), miseInstallsGenerate))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// getMiseInstallsPath returns the mise installs path based on environment variables.
// Priority:
// 1. $MISE_DATA_DIR/installs
// 2. $XDG_DATA_HOME/mise/installs
// 3. ~/.local/share/mise/installs (default)
func getMiseInstallsPath() string {
	// Check MISE_DATA_DIR first
	if miseDataDir := os.Getenv("MISE_DATA_DIR"); miseDataDir != "" {
		return filepath.Join(miseDataDir, "installs")
	}

	// Check XDG_DATA_HOME
	if xdgDataHome := os.Getenv("XDG_DATA_HOME"); xdgDataHome != "" {
		return filepath.Join(xdgDataHome, "mise", "installs")
	}

	// Default to ~/.local/share/mise/installs
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".local", "share", "mise", "installs")
}

// MiseInstall represents a mise-installed tool
type MiseInstall struct {
	Tool        string
	Version     string
	InstallPath string
	InstalledAt time.Time
}

func miseInstallsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("tool"),
		table.TextColumn("version"),
		table.TextColumn("install_path"),
		table.BigIntColumn("installed_at"),
	}
}

func miseInstallsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	basePath := getMiseInstallsPath()
	if basePath == "" {
		return []map[string]string{}, nil
	}

	installs, err := collectMiseInstalls(basePath)
	if err != nil {
		// Gracefully return empty result if mise installs cannot be read
		return []map[string]string{}, nil
	}

	results := make([]map[string]string, 0, len(installs))
	for _, install := range installs {
		results = append(results, map[string]string{
			"tool":         install.Tool,
			"version":      install.Version,
			"install_path": install.InstallPath,
			"installed_at": strconv.FormatInt(install.InstalledAt.Unix(), 10),
		})
	}

	return results, nil
}

func collectMiseInstalls(basePath string) ([]MiseInstall, error) {
	var installs []MiseInstall

	// Check if mise installs directory exists
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return installs, nil
	}

	// Read tool directories
	toolDirs, err := os.ReadDir(basePath)
	if err != nil {
		return nil, err
	}

	for _, toolDir := range toolDirs {
		if !toolDir.IsDir() {
			continue
		}

		toolName := toolDir.Name()
		toolPath := filepath.Join(basePath, toolName)

		// Read version directories for this tool
		versionDirs, err := os.ReadDir(toolPath)
		if err != nil {
			continue
		}

		for _, versionDir := range versionDirs {
			if !versionDir.IsDir() {
				continue
			}

			version := versionDir.Name()
			installPath := filepath.Join(toolPath, version)

			// Get install time from directory modification time
			info, err := versionDir.Info()
			var installedAt time.Time
			if err == nil {
				installedAt = info.ModTime()
			}

			installs = append(installs, MiseInstall{
				Tool:        toolName,
				Version:     version,
				InstallPath: installPath,
				InstalledAt: installedAt,
			})
		}
	}

	return installs, nil
}
