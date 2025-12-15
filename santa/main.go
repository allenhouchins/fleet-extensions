package main

import (
	"context"
	"flag"
	"log"
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
		"santa",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// Register the tables
	server.RegisterPlugin(table.NewPlugin("santa_rules", santaRulesColumns(), generateSantaRules))
	server.RegisterPlugin(table.NewPlugin("santa_allowed", santaAllowedColumns(), generateSantaAllowed))
	server.RegisterPlugin(table.NewPlugin("santa_denied", santaDeniedColumns(), generateSantaDenied))
	server.RegisterPlugin(santaStatusTablePlugin())

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

// santaRulesColumns returns the column definitions for the santa_rules table
func santaRulesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("identifier"),
		table.TextColumn("type"),
		table.TextColumn("state"),
		table.TextColumn("custom_message"),
	}
}

// santaAllowedColumns returns the column definitions for the santa_allowed table
func santaAllowedColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("timestamp"),
		table.TextColumn("application"),
		table.TextColumn("reason"),
		table.TextColumn("sha256"),
	}
}

// santaDeniedColumns returns the column definitions for the santa_denied table
func santaDeniedColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("timestamp"),
		table.TextColumn("application"),
		table.TextColumn("reason"),
		table.TextColumn("sha256"),
	}
}

// generateSantaRules generates data for the santa_rules table
func generateSantaRules(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	rules, err := collectSantaRules()
	if err != nil {
		// Gracefully return an empty result if rules cannot be collected
		return []map[string]string{}, nil
	}

	var results []map[string]string
	for _, rule := range rules {
		row := map[string]string{
			"identifier":     rule.Identifier,
			"type":           GetRuleTypeName(rule.Type),
			"state":          GetRuleStateName(rule.State),
			"custom_message": rule.CustomMessage,
		}
		results = append(results, row)
	}

	return results, nil
}

// generateSantaAllowed generates data for the santa_allowed table
func generateSantaAllowed(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	entries, err := scrapeSantaLog(ctx, DecisionAllowed)
	if err != nil {
		// Gracefully return an empty result if log cannot be scraped
		return []map[string]string{}, nil
	}

	results := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		results = append(results, map[string]string{
			"timestamp":   entry.Timestamp,
			"application": entry.Application,
			"reason":      entry.Reason,
			"sha256":      entry.SHA256,
		})
	}

	return results, nil
}

// generateSantaDenied generates data for the santa_denied table
func generateSantaDenied(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	entries, err := scrapeSantaLog(ctx, DecisionDenied)
	if err != nil {
		// Gracefully return an empty result if log cannot be scraped
		return []map[string]string{}, nil
	}

	results := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		results = append(results, map[string]string{
			"timestamp":   entry.Timestamp,
			"application": entry.Application,
			"reason":      entry.Reason,
			"sha256":      entry.SHA256,
		})
	}

	return results, nil
}
