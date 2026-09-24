package main

import (
	"context"
	"flag"
	"log"
	"strings"
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
	verbose = flag.Bool("verbose", false, "Log sshd invocation diagnostics to stderr")
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
		"sshd_config",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"sshd_config",
		sshdConfigColumns(),
		generateSSHDConfig,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func sshdConfigColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("keyword"),
		table.TextColumn("value"),
		table.TextColumn("connection_spec"),
	}
}

func generateSSHDConfig(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	sshdPath := findSSHD()
	if sshdPath == "" {
		if *verbose {
			log.Printf("sshd_config: no sshd binary found, returning no rows")
		}
		return []map[string]string{}, nil
	}

	// Without a connection_spec constraint, report the global configuration:
	// sshd evaluates no Match blocks unless it is given -C.
	specs := connectionSpecs(queryContext)
	if len(specs) == 0 {
		specs = []string{""}
	}

	results := []map[string]string{}
	for _, spec := range specs {
		output, args, err := dumpConfig(ctx, sshdPath, spec)
		if err != nil {
			return nil, err
		}
		if *verbose {
			log.Printf("sshd_config: ran %s %s", sshdPath, strings.Join(args, " "))
		}
		for _, entry := range parseConfig(output) {
			results = append(results, map[string]string{
				"keyword":         entry.Keyword,
				"value":           entry.Value,
				"connection_spec": spec,
			})
		}
	}
	return results, nil
}

// connectionSpecs returns the distinct values of every equality constraint on
// connection_spec, which covers both `=` and `IN (...)`.
func connectionSpecs(queryContext table.QueryContext) []string {
	list, ok := queryContext.Constraints["connection_spec"]
	if !ok {
		return nil
	}

	var specs []string
	seen := make(map[string]bool)
	for _, c := range list.Constraints {
		if c.Operator != table.OperatorEquals || seen[c.Expression] {
			continue
		}
		seen[c.Expression] = true
		specs = append(specs, c.Expression)
	}
	return specs
}
