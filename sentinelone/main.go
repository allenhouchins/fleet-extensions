// ABOUTME: SentinelOne osquery extension - provides endpoint security status and threat intelligence
// ABOUTME: Supports macOS and Windows platforms via sentinelctl CLI tool

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	var socketPath string = ":0" // default
	for i, arg := range os.Args {
		if (arg == "-socket" || arg == "--socket") && i+1 < len(os.Args) {
			socketPath = os.Args[i+1]
			break
		}
	}

	plugin := table.NewPlugin("sentinelone_info", SentinelOneColumns(), SentinelOneGenerate)

	srv, err := osquery.NewExtensionManagerServer("sentinelone", socketPath)
	if err != nil {
		panic(err)
	}

	srv.RegisterPlugin(plugin)

	if err := srv.Run(); err != nil {
		panic(err)
	}
}

// sentinelCtlPaths defines platform-specific CLI tool locations
var sentinelCtlPaths = map[string][]string{
	"windows": {
		`C:\Program Files\SentinelOne\Sentinel Agent *\SentinelCtl.exe`,
		`C:\Program Files (x86)\SentinelOne\Sentinel Agent *\SentinelCtl.exe`,
	},
	"darwin": {
		"/usr/local/bin/sentinelctl",
		"/opt/sentinelone/bin/sentinelctl",
	},
}

// SentinelOneOutput represents parsed data from sentinelctl
type SentinelOneOutput struct {
	AgentID                 string
	AgentVersion            string
	AgentLoaded             bool
	MonitorLoaded           bool
	ProtectionStatus        string
	InfectedStatus          string
	SelfProtectionStatus    string
	NetworkQuarantineStatus string
	InstallDate             string
	ESFrameworkStatus       string // macOS only
	FWExtensionStatus       string // macOS only
}

// SentinelOneColumns defines the table schema
func SentinelOneColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("agent_id"),
		table.TextColumn("agent_version"),
		table.TextColumn("agent_loaded"),
		table.TextColumn("monitor_loaded"),
		table.TextColumn("protection_status"),
		table.TextColumn("infected_status"),
		table.TextColumn("self_protection_status"),
		table.TextColumn("network_quarantine_status"),
		table.TextColumn("install_date"),
		table.TextColumn("es_framework_status"),
		table.TextColumn("fw_extension_status"),
	}
}

// SentinelOneGenerate executes sentinelctl and returns parsed data
func SentinelOneGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string
	var output SentinelOneOutput
	var err error

	switch runtime.GOOS {
	case "darwin":
		output, err = runSentinelOneDarwin()
		if err != nil {
			fmt.Printf("sentinelone error (darwin): %v\n", err)
			return nil, err
		}

	case "windows":
		output, err = runSentinelOneWindows()
		if err != nil {
			fmt.Printf("sentinelone error (windows): %v\n", err)
			return nil, err
		}

	case "linux":
		// Linux support deferred to future phase
		fmt.Println("sentinelone: Linux platform not yet supported")
		return results, nil

	default:
		return results, nil
	}

	// Require critical fields: agent_version and protection_status
	if output.AgentVersion == "" || output.ProtectionStatus == "" {
		// Missing critical fields - return empty result
		return results, nil
	}

	results = append(results, map[string]string{
		"agent_id":                   output.AgentID,
		"agent_version":              output.AgentVersion,
		"agent_loaded":               boolToString(output.AgentLoaded),
		"monitor_loaded":             boolToString(output.MonitorLoaded),
		"protection_status":          output.ProtectionStatus,
		"infected_status":            output.InfectedStatus,
		"self_protection_status":     output.SelfProtectionStatus,
		"network_quarantine_status":  output.NetworkQuarantineStatus,
		"install_date":               output.InstallDate,
		"es_framework_status":        output.ESFrameworkStatus,
		"fw_extension_status":        output.FWExtensionStatus,
	})

	return results, nil
}

// boolToString converts bool to string representation
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// findSentinelCtl locates the sentinelctl binary for the current platform
func findSentinelCtl() (string, error) {
	paths, ok := sentinelCtlPaths[runtime.GOOS]
	if !ok {
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	for _, pathPattern := range paths {
		if runtime.GOOS == "windows" {
			// Use glob for Windows to handle version directories
			matches, err := filepath.Glob(pathPattern)
			if err != nil {
				continue
			}
			if len(matches) > 0 {
				// Return first match (could enhance to sort by version)
				return matches[0], nil
			}
		} else {
			// Direct path check for Unix-like systems
			if _, err := os.Stat(pathPattern); err == nil {
				return pathPattern, nil
			}
		}
	}

	return "", fmt.Errorf("sentinelctl not found")
}

// runCommand executes a command and returns output
func runCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

// runSentinelOneWindows executes SentinelCtl.exe on Windows and parses output
func runSentinelOneWindows() (SentinelOneOutput, error) {
	var output SentinelOneOutput

	sentinelCtlPath, err := findSentinelCtl()
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return output, nil // Not installed - return empty
		}
		return output, err
	}

	out, err := runCommand(sentinelCtlPath, "status")
	if err != nil {
		// Check for permission denied
		if strings.Contains(err.Error(), "Access is denied") {
			fmt.Println("sentinelctl requires administrator privileges")
			return output, nil // Return empty, not error
		}
		return output, fmt.Errorf("executing sentinelctl status: %w", err)
	}

	return parseWindowsOutput(string(out)), nil
}

// parseWindowsOutput parses SentinelCtl.exe status output
func parseWindowsOutput(cmdOut string) SentinelOneOutput {
	var output SentinelOneOutput
	out := strings.ToLower(cmdOut)

	// Agent loaded status
	agentLoadedRe := regexp.MustCompile(`sentinelagent is (loaded|not loaded)`)
	if match := agentLoadedRe.FindStringSubmatch(out); len(match) > 1 {
		output.AgentLoaded = match[1] == "loaded"
	}

	// Monitor loaded status
	monitorLoadedRe := regexp.MustCompile(`sentinelmonitor is (loaded|not loaded)`)
	if match := monitorLoadedRe.FindStringSubmatch(out); len(match) > 1 {
		output.MonitorLoaded = match[1] == "loaded"
	}

	// Self-protection status
	selfProtectionRe := regexp.MustCompile(`self-protection status:\s*(on|off)`)
	if match := selfProtectionRe.FindStringSubmatch(out); len(match) > 1 {
		output.SelfProtectionStatus = strings.Title(match[1])
	}

	// Monitor Build ID (for version extraction)
	buildIDRe := regexp.MustCompile(`monitor build id:\s*([0-9.]+)`)
	if match := buildIDRe.FindStringSubmatch(out); len(match) > 1 {
		output.AgentVersion = match[1]
	}

	// Set protection status based on agent loaded state
	if output.AgentLoaded {
		output.ProtectionStatus = "On"
	} else {
		output.ProtectionStatus = "Off"
	}

	return output
}

// runSentinelOneDarwin executes sentinelctl on macOS and parses output
func runSentinelOneDarwin() (SentinelOneOutput, error) {
	var output SentinelOneOutput

	sentinelCtlPath, err := findSentinelCtl()
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return output, nil // Not installed - return empty
		}
		return output, err
	}

	out, err := runCommand(sentinelCtlPath, "status")
	if err != nil {
		// Check for permission denied
		if strings.Contains(err.Error(), "permission denied") {
			fmt.Println("sentinelctl requires elevated privileges or Full Disk Access")
			return output, nil // Return empty, not error
		}
		return output, fmt.Errorf("executing sentinelctl status: %w", err)
	}

	return parseDarwinOutput(string(out)), nil
}

// parseDarwinOutput parses sentinelctl status output on macOS
func parseDarwinOutput(cmdOut string) SentinelOneOutput {
	var output SentinelOneOutput

	// Case-insensitive patterns with flexible whitespace
	patterns := map[string]*regexp.Regexp{
		"version":        regexp.MustCompile(`(?i)Agent Version:\s*(.+)`),
		"id":             regexp.MustCompile(`(?i)ID:\s*([a-f0-9-]+)`),
		"install_date":   regexp.MustCompile(`(?i)Install Date:\s*(.+)`),
		"protection":     regexp.MustCompile(`(?i)Protection status:\s*(On|Off)`),
		"infected":       regexp.MustCompile(`(?i)Infected status:\s*(.+)`),
		"es_framework":   regexp.MustCompile(`(?i)ES Framework status:\s*(.+)`),
		"fw_extension":   regexp.MustCompile(`(?i)FW Extension status:\s*(.+)`),
		"net_quarantine": regexp.MustCompile(`(?i)Network Quarantine status:\s*(.+)`),
	}

	// Parse all fields
	if match := patterns["version"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.AgentVersion = strings.TrimSpace(match[1])
	}

	if match := patterns["id"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.AgentID = strings.TrimSpace(match[1])
	}

	if match := patterns["install_date"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.InstallDate = strings.TrimSpace(match[1])
	}

	if match := patterns["protection"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.ProtectionStatus = strings.TrimSpace(match[1])
	}

	if match := patterns["infected"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.InfectedStatus = strings.TrimSpace(match[1])
	}

	if match := patterns["es_framework"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.ESFrameworkStatus = strings.TrimSpace(match[1])
	}

	if match := patterns["fw_extension"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.FWExtensionStatus = strings.TrimSpace(match[1])
	}

	if match := patterns["net_quarantine"].FindStringSubmatch(cmdOut); len(match) > 1 {
		output.NetworkQuarantineStatus = strings.TrimSpace(match[1])
	}

	// Infer agent loaded from ES Framework status (case-insensitive)
	if strings.EqualFold(output.ESFrameworkStatus, "Running") {
		output.AgentLoaded = true
	}

	return output
}
