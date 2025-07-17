package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// sectionToDataType maps section names to their corresponding data types
var sectionToDataType = map[string]string{
	"Apple Pay":                    "SPSecureElementDataType",
	"Audio":                        "SPAudioDataType",
	"Bluetooth":                    "SPBluetoothDataType",
	"Camera":                       "SPCameraDataType",
	"Controller":                   "SPHardwareDataType",
	"Firewall":                     "SPFirewallDataType",
	"Graphics/Displays":            "SPDisplaysDataType",
	"Hardware":                     "SPHardwareDataType",
	"Language & Region":            "SPInternationalDataType",
	"Locations":                    "SPNetworkLocationDataType",
	"Memory":                       "SPMemoryDataType",
	"NVMExpress":                   "SPNVMeDataType",
	"Network":                      "SPNetworkDataType",
	"Power":                        "SPPowerDataType",
	"Printer Software":             "SPPrintersSoftwareDataType",
	"Printers":                     "SPPrintersDataType",
	"Software":                     "SPSoftwareDataType",
	"SPI":                          "SPSPIDataType",
	"Storage":                      "SPStorageDataType",
	"Thunderbolt/USB4":             "SPThunderboltDataType",
	"USB":                          "SPUSBDataType",
	"Volumes":                      "SPNetworkVolumeDataType",
	"Wi-Fi":                        "SPAirPortDataType",
}

func main() {
	var socketPath string = ":0" // default
	for i, arg := range os.Args {
		if (arg == "-socket" || arg == "--socket") && i+1 < len(os.Args) {
			socketPath = os.Args[i+1]
			break
		}
	}

	plugin := table.NewPlugin("system_profiler", SystemProfilerColumns(), SystemProfilerGenerate)

	srv, err := osquery.NewExtensionManagerServer("system_profiler", socketPath)
	if err != nil {
		panic(err)
	}

	srv.RegisterPlugin(plugin)

	if err := srv.Run(); err != nil {
		panic(err)
	}
}

// SystemProfilerColumns returns the columns for the system_profiler table
func SystemProfilerColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("section"),
		table.TextColumn("subsection"),
		table.TextColumn("key"),
		table.TextColumn("value"),
		table.TextColumn("data_type"),
	}
}

// SystemProfilerGenerate generates the data for the system_profiler table
func SystemProfilerGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	// Only run on macOS
	if runtime.GOOS != "darwin" {
		return results, nil
	}

	// Execute the system_profiler command
	cmd := exec.Command("/usr/sbin/system_profiler", "-detailLevel", "basic")
	output, err := cmd.Output()
	if err != nil {
		return results, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentSection, currentSubsection string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			continue
		}

		// Top-level section: no leading spaces, ends with :
		if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(line, " ") {
			currentSection = strings.TrimSuffix(trimmed, ":")
			currentSubsection = ""
			continue
		}

		// Subsection: exactly 4 leading spaces, ends with :
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && strings.HasSuffix(trimmed, ":") {
			currentSubsection = strings.TrimSuffix(trimmed, ":")
			continue
		}

		// Key-value: must contain ": "
		if idx := strings.Index(trimmed, ": "); idx != -1 {
			key := trimmed[:idx]
			value := trimmed[idx+2:]
			row := make(map[string]string)
			row["section"] = currentSection
			row["subsection"] = currentSubsection
			row["key"] = key
			row["value"] = value
			row["data_type"] = sectionToDataType[currentSection]
			results = append(results, row)
		}
	}

	return results, scanner.Err()
} 