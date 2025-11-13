package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"time"

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

	plugin := table.NewPlugin("ubuntu_pro_status", UbuntuProColumns(), UbuntuProGenerate)

	srv, err := osquery.NewExtensionManagerServer("ubuntu_pro", socketPath)
	if err != nil {
		panic(err)
	}

	srv.RegisterPlugin(plugin)

	if err := srv.Run(); err != nil {
		panic(err)
	}
}

// ProStatus represents the JSON output from `pro status --format json`
type ProStatus struct {
	Attached bool `json:"attached"`
	Account  struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	} `json:"account"`
	Contract struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		Expires   time.Time `json:"expires"`
	} `json:"contract"`
	Services []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Entitled    string `json:"entitled"`
		Status      string `json:"status"`
	} `json:"services"`
	Version string `json:"version"`
}

// UbuntuProColumns returns the columns for the ubuntu_pro_status table
func UbuntuProColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("attached"),
		table.TextColumn("account_name"),
		table.TextColumn("account_id"),
		table.TextColumn("contract_id"),
		table.TextColumn("contract_name"),
		table.TextColumn("contract_created_at"),
		table.TextColumn("contract_expires"),
		table.IntegerColumn("days_until_expiration"),
		table.TextColumn("version"),
		// Service columns
		table.TextColumn("esm_infra_status"),
		table.TextColumn("esm_infra_entitled"),
		table.TextColumn("esm_apps_status"),
		table.TextColumn("esm_apps_entitled"),
		table.TextColumn("livepatch_status"),
		table.TextColumn("livepatch_entitled"),
		table.TextColumn("fips_status"),
		table.TextColumn("fips_entitled"),
		table.TextColumn("cis_status"),
		table.TextColumn("cis_entitled"),
		// Error handling
		table.TextColumn("error"),
	}
}

// UbuntuProGenerate generates the data for the ubuntu_pro_status table
func UbuntuProGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// Check if pro command exists
	if _, err := exec.LookPath("pro"); err != nil {
		return []map[string]string{{
			"attached": "0",
			"error":    "pro command not found - ubuntu-advantage-tools not installed",
		}}, nil
	}

	// Execute `pro status --format json`
	cmd := exec.CommandContext(ctx, "pro", "status", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		return []map[string]string{{
			"attached": "0",
			"error":    "failed to execute pro status: " + err.Error(),
		}}, nil
	}

	// Parse JSON output
	var status ProStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return []map[string]string{{
			"attached": "0",
			"error":    "failed to parse JSON: " + err.Error(),
		}}, nil
	}

	// Build result row
	row := map[string]string{
		"attached":              boolToInt(status.Attached),
		"account_name":          status.Account.Name,
		"account_id":            status.Account.ID,
		"contract_id":           status.Contract.ID,
		"contract_name":         status.Contract.Name,
		"contract_created_at":   formatTime(status.Contract.CreatedAt),
		"contract_expires":      formatTime(status.Contract.Expires),
		"days_until_expiration": calculateDaysUntilExpiration(status.Contract.Expires),
		"version":               status.Version,
		"error":                 "",
		// Initialize service columns with defaults
		"esm_infra_status":    "n/a",
		"esm_infra_entitled":  "no",
		"esm_apps_status":     "n/a",
		"esm_apps_entitled":   "no",
		"livepatch_status":    "n/a",
		"livepatch_entitled":  "no",
		"fips_status":         "n/a",
		"fips_entitled":       "no",
		"cis_status":          "n/a",
		"cis_entitled":        "no",
	}

	// Extract service statuses
	for _, service := range status.Services {
		switch service.Name {
		case "esm-infra":
			row["esm_infra_status"] = service.Status
			row["esm_infra_entitled"] = service.Entitled
		case "esm-apps":
			row["esm_apps_status"] = service.Status
			row["esm_apps_entitled"] = service.Entitled
		case "livepatch":
			row["livepatch_status"] = service.Status
			row["livepatch_entitled"] = service.Entitled
		case "fips":
			row["fips_status"] = service.Status
			row["fips_entitled"] = service.Entitled
		case "cis":
			row["cis_status"] = service.Status
			row["cis_entitled"] = service.Entitled
		}
	}

	return []map[string]string{row}, nil
}

// Helper: Convert bool to "0" or "1" string for INTEGER column
func boolToInt(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Helper: Format time to RFC3339 (ISO 8601) or empty string if zero
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Helper: Calculate days until expiration
func calculateDaysUntilExpiration(expires time.Time) string {
	if expires.IsZero() {
		return "-1"
	}
	days := int(time.Until(expires).Hours() / 24)
	return strconv.Itoa(days)
}
