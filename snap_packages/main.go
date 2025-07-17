package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
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

	plugin := table.NewPlugin("snap_packages", SnapPackagesColumns(), SnapPackagesGenerate)

	srv, err := osquery.NewExtensionManagerServer("snap_packages", socketPath)
	if err != nil {
		panic(err)
	}

	srv.RegisterPlugin(plugin)

	if err := srv.Run(); err != nil {
		panic(err)
	}
}

// SnapPackagesColumns returns the columns for the snap_packages table
func SnapPackagesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("version"),
		table.TextColumn("rev"),
		table.TextColumn("tracking"),
		table.TextColumn("publisher"),
		table.TextColumn("notes"),
	}
}

// SnapPackagesGenerate generates the data for the snap_packages table
func SnapPackagesGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	// Execute the snap list command
	cmd := exec.Command("/usr/bin/snap", "list")
	output, err := cmd.Output()
	if err != nil {
		return results, err
	}

	// Parse the output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineCount++

		// Skip the first two lines (header and separator)
		if lineCount <= 2 {
			continue
		}

		// Skip empty lines
		if line == "" {
			continue
		}

		// Split the line by whitespace
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Create a row
		row := make(map[string]string)
		row["name"] = fields[0]
		row["version"] = fields[1]
		row["rev"] = fields[2]
		row["tracking"] = fields[3]
		row["publisher"] = fields[4]

		// Notes column may not always be present
		if len(fields) > 5 {
			row["notes"] = fields[5]
		} else {
			row["notes"] = ""
		}

		results = append(results, row)
	}

	return results, scanner.Err()
}
