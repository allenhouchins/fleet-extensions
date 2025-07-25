package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"os/exec"
	"regexp"
	"runtime"
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
		"nuget_packages",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"nuget_packages",
		nugetPackagesColumns(),
		generateNugetPackages,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func nugetPackagesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("version"),
		table.TextColumn("description"),
	}
}

func getNugetCommand(args ...string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("nuget.exe", args...)
	}
	return exec.Command("/opt/homebrew/bin/nuget", args...)
}

func generateNugetPackages(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	cmd := getNugetCommand("search", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	results := []map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var name, version, description string
	packageLine := regexp.MustCompile(`^> ([^|]+) \| ([^|]+) \| .*$`)
	for scanner.Scan() {
		line := scanner.Text()
		if matches := packageLine.FindStringSubmatch(line); matches != nil {
			name = strings.TrimSpace(matches[1])
			version = strings.TrimSpace(matches[2])
			description = ""
			continue
		}
		if strings.HasPrefix(line, "  ") && name != "" && version != "" {
			description = strings.TrimSpace(line)
			results = append(results, map[string]string{
				"name":        name,
				"version":     version,
				"description": description,
			})
			name, version, description = "", "", ""
		}
	}
	return results, nil
}
