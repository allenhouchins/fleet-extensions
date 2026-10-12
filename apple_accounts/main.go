package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
	// osquery passes --verbose to every autoloaded extension when it is itself
	// running verbose. Without this flag the process would exit at flag
	// parsing and the table would silently never register.
	verbose = flag.Bool("verbose", false, "Log each accounts database read to stderr")
)

// listUsers is swapped out in tests.
var listUsers = localUsers

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
		"apple_accounts",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"apple_accounts",
		appleAccountsColumns(),
		generateAppleAccounts,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func appleAccountsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.BigIntColumn("uid"),
		table.TextColumn("username"),
		table.TextColumn("apple_account"),
		table.IntegerColumn("active"),
		table.IntegerColumn("authenticated"),
		table.TextColumn("path"),
	}
}

func generateAppleAccounts(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	results := []map[string]string{}
	for _, u := range listUsers(ctx) {
		path := filepath.Join(u.HomeDir, accountsDB)
		accounts, err := readAppleAccounts(ctx, u.HomeDir)
		if errors.Is(err, fs.ErrNotExist) {
			// The user has never used anything backed by the Accounts
			// framework, so there is nobody signed in.
			continue
		}
		if err != nil {
			// Failing the query, rather than skipping the user, keeps a
			// database osqueryd cannot read from looking like a user who is
			// not signed in, which a policy would count as a pass.
			if errors.Is(err, fs.ErrPermission) {
				return nil, fmt.Errorf("reading %s: %w (Full Disk Access required)", path, err)
			}
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		if *verbose {
			log.Printf("apple_accounts: %d Apple Account(s) in %s", len(accounts), path)
		}
		for _, a := range accounts {
			results = append(results, map[string]string{
				"uid":           u.UID,
				"username":      u.Username,
				"apple_account": a.AppleAccount,
				"active":        a.Active,
				"authenticated": a.Authenticated,
				"path":          path,
			})
		}
	}
	return results, nil
}
