package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

const (
	cacheDir  = "/private/var/tmp/sofa"
	jsonCache = cacheDir + "/macos_data_feed.json"
	etagCache = cacheDir + "/macos_data_feed_etag.txt"
	sofaURL   = "https://sofafeed.macadmins.io/v1/macos_data_feed.json"
	userAgent = "SOFA-osquery-macOSCompatibilityCheck/1.0"
)

type SofaFeed struct {
	OSVersions []struct {
		OSVersion string `json:"OSVersion"`
	} `json:"OSVersions"`
	Models map[string]struct {
		SupportedOS []string `json:"SupportedOS"`
	} `json:"Models"`
}

func ensureCacheDir() error {
	return os.MkdirAll(cacheDir, 0755)
}

func readFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func writeFile(filename, content string) error {
	return ioutil.WriteFile(filename, []byte(content), 0644)
}

func fetchSofaJson() (string, error) {
	if err := ensureCacheDir(); err != nil {
		return "", err
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", sofaURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)

	// ETag support
	if etag, err := readFile(etagCache); err == nil && strings.TrimSpace(etag) != "" {
		req.Header.Set("If-None-Match", strings.TrimSpace(etag))
	}

	resp, err := client.Do(req)
	if err != nil {
		// fallback to cache
		return readFile(jsonCache)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return readFile(jsonCache)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Save ETag if present
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = writeFile(etagCache, etag)
	}

	if resp.StatusCode == http.StatusOK {
		_ = writeFile(jsonCache, string(body))
		return string(body), nil
	}

	// fallback to cache
	return readFile(jsonCache)
}

func macosCompatibilityColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("system_version"),
		table.TextColumn("system_os_major"),
		table.TextColumn("model_identifier"),
		table.TextColumn("latest_macos"),
		table.TextColumn("latest_compatible_macos"),
		table.IntegerColumn("is_compatible"),
		table.TextColumn("status"),
	}
}

func getSystemVersion() string {
	cmd := exec.Command("/usr/bin/sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func getSystemOsMajor(systemVersion string) string {
	// macOS version is usually in the form "13.4.1" or "14.0"
	parts := strings.Split(systemVersion, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return "Unknown"
}

func getModelIdentifier() string {
	cmd := exec.Command("/usr/sbin/sysctl", "-n", "hw.model")
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}
	return strings.TrimSpace(string(output))
}

func macosCompatibilityGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	systemVersion := getSystemVersion()
	systemOsMajor := getSystemOsMajor(systemVersion)
	modelIdentifier := getModelIdentifier()

	jsonData, err := fetchSofaJson()
	if err != nil || jsonData == "" {
		return []map[string]string{{
			"system_version":          systemVersion,
			"system_os_major":         systemOsMajor,
			"model_identifier":        modelIdentifier,
			"latest_macos":            "Unknown",
			"latest_compatible_macos": "Unknown",
			"is_compatible":           "-1",
			"status":                  "Could not obtain data",
		}}, nil
	}

	var feed SofaFeed
	err = json.Unmarshal([]byte(jsonData), &feed)
	if err != nil {
		return []map[string]string{{
			"system_version":          systemVersion,
			"system_os_major":         systemOsMajor,
			"model_identifier":        modelIdentifier,
			"latest_macos":            "Error",
			"latest_compatible_macos": "Error",
			"is_compatible":           "-1",
			"status":                  "Error parsing data: " + err.Error(),
		}}, nil
	}

	latestOS := "Unknown"
	if len(feed.OSVersions) > 0 {
		latestOS = feed.OSVersions[0].OSVersion
	}
	latestCompatibleOS := "Unsupported"
	status := "Pass"

	if strings.Contains(modelIdentifier, "VirtualMac") {
		modelIdentifier = "Macmini9,1"
	}

	if model, ok := feed.Models[modelIdentifier]; ok && len(model.SupportedOS) > 0 {
		latestCompatibleOS = model.SupportedOS[0]
	} else {
		status = "Unsupported Hardware"
	}

	isCompatible := 0
	if latestOS == latestCompatibleOS && status != "Unsupported Hardware" {
		isCompatible = 1
	} else if status != "Unsupported Hardware" {
		status = "Fail"
	}

	return []map[string]string{{
		"system_version":          systemVersion,
		"system_os_major":         systemOsMajor,
		"model_identifier":        modelIdentifier,
		"latest_macos":            latestOS,
		"latest_compatible_macos": latestCompatibleOS,
		"is_compatible":           fmt.Sprintf("%d", isCompatible),
		"status":                  status,
	}}, nil
}

func main() {
	var socketPath string = ":0" // default
	for i, arg := range os.Args {
		if (arg == "-socket" || arg == "--socket") && i+1 < len(os.Args) {
			socketPath = os.Args[i+1]
			break
		}
	}

	server, err := osquery.NewExtensionManagerServer("macos_compatibility", socketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %v", err)
	}

	plugin := table.NewPlugin("macos_compatibility", macosCompatibilityColumns(), macosCompatibilityGenerate)
	server.RegisterPlugin(plugin)

	if err := server.Run(); err != nil {
		log.Fatalf("Error running extension: %v", err)
	}
}
