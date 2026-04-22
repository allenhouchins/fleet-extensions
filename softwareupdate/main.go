package main

import (
	"context"
	"flag"
	"log"
	"os/exec"
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
		"softwareupdate",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"softwareupdate",
		softwareUpdateColumns(),
		generateSoftwareUpdate,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func softwareUpdateColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("label"),
		table.TextColumn("title"),
		table.TextColumn("version"),
		table.TextColumn("size"),
		table.TextColumn("recommended"),
		table.TextColumn("action"),
	}
}

func generateSoftwareUpdate(_ context.Context, _ table.QueryContext) ([]map[string]string, error) {
	if runtime.GOOS != "darwin" {
		return []map[string]string{}, nil
	}

	cmd := exec.Command("/usr/sbin/softwareupdate", "--list", "--verbose")
	output, err := cmd.Output()
	rows := parseSoftwareUpdateList(string(output))
	if err != nil && len(rows) == 0 {
		return nil, err
	}
	return rows, nil
}

func parseSoftwareUpdateList(output string) []map[string]string {
	var results []map[string]string

	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")

	var pendingLabel string
	flush := func() {
		if pendingLabel == "" {
			return
		}
		results = append(results, map[string]string{
			"label":       pendingLabel,
			"title":       "",
			"version":     "",
			"size":        "",
			"recommended": "",
			"action":      "",
		})
		pendingLabel = ""
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "* Label:") {
			flush()
			pendingLabel = strings.TrimSpace(strings.TrimPrefix(trimmed, "* Label:"))
			continue
		}

		if pendingLabel == "" {
			continue
		}

		detail := strings.TrimLeft(line, " \t")
		if !strings.HasPrefix(detail, "Title:") && !strings.Contains(detail, "Version:") {
			continue
		}

		row := map[string]string{
			"label":       pendingLabel,
			"title":       extractBetweenKeys(detail, "Title:", ", Version:"),
			"version":     extractBetweenKeys(detail, "Version:", ", Size:"),
			"size":        extractBetweenKeys(detail, "Size:", ", Recommended:"),
			"recommended": extractRecommended(detail),
			"action":      extractAction(detail),
		}
		results = append(results, row)
		pendingLabel = ""
	}

	flush()
	return results
}

func extractBetweenKeys(s, start, end string) string {
	i := strings.Index(s, start)
	if i == -1 {
		return ""
	}
	rest := strings.TrimSpace(s[i+len(start):])
	if end == "" {
		return trimTrailingComma(rest)
	}
	j := strings.Index(rest, end)
	if j == -1 {
		return trimTrailingComma(rest)
	}
	return trimTrailingComma(strings.TrimSpace(rest[:j]))
}

func extractRecommended(s string) string {
	if !strings.Contains(s, "Recommended:") {
		return ""
	}
	i := strings.Index(s, "Recommended:")
	rest := strings.TrimSpace(s[i+len("Recommended:"):])
	if j := strings.Index(rest, ", Action:"); j != -1 {
		return trimTrailingComma(strings.TrimSpace(rest[:j]))
	}
	return trimTrailingComma(rest)
}

func extractAction(s string) string {
	if !strings.Contains(s, "Action:") {
		return ""
	}
	i := strings.Index(s, "Action:")
	rest := strings.TrimSpace(s[i+len("Action:"):])
	return trimTrailingComma(rest)
}

func trimTrailingComma(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), ",")
}
