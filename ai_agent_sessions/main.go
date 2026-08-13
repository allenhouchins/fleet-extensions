package main

import (
	"context"
	"flag"
	"log"
	"sort"
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
	verbose    = flag.Bool("verbose", false, "Log scan diagnostics to stderr")
	maxAgeDays = flag.Int("max-age-days", 30, "Only report sessions written within this many days (0 for all history)")

	// Limits for ai_agent_session_messages, which returns conversation text
	// and is unbounded without them.
	maxRows         = flag.Int("max-rows", 5000, "Maximum ai_agent_session_messages rows per query (0 for no limit)")
	maxContentBytes = flag.Int("max-content-bytes", 8192, "Truncate each content block to this many bytes (0 for no limit)")
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
		"ai_agent_sessions",
		*socket,
		serverTimeout,
		serverPingInterval,
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"ai_agent_sessions",
		aiAgentSessionsColumns(),
		generateAIAgentSessions,
	))
	server.RegisterPlugin(table.NewPlugin(
		"ai_agent_session_messages",
		aiAgentSessionMessagesColumns(),
		generateAIAgentSessionMessages,
	))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func aiAgentSessionsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("agent"),
		table.TextColumn("session_id"),
		table.TextColumn("username"),
		table.TextColumn("project_path"),
		table.TextColumn("git_branch"),
		table.TextColumn("git_repository"),
		table.TextColumn("agent_version"),
		table.TextColumn("model"),
		table.BigIntColumn("started_at"),
		table.BigIntColumn("ended_at"),
		table.BigIntColumn("duration_seconds"),
		table.BigIntColumn("user_messages"),
		table.BigIntColumn("assistant_messages"),
		table.BigIntColumn("tool_calls"),
		table.BigIntColumn("input_tokens"),
		table.BigIntColumn("output_tokens"),
		table.BigIntColumn("cache_read_tokens"),
		table.BigIntColumn("cache_write_tokens"),
		table.TextColumn("transcript_path"),
		table.BigIntColumn("transcript_size_bytes"),
	}
}

func generateAIAgentSessions(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	started := time.Now()

	users := discoverUsers()
	sessions := collectSessions(users, cutoffTime(started, *maxAgeDays))

	if *verbose {
		log.Printf("ai_agent_sessions: scanned %d home directories, found %d sessions in %s",
			len(users), len(sessions), time.Since(started).Round(time.Millisecond))
	}

	results := make([]map[string]string, 0, len(sessions))
	for _, s := range sessions {
		results = append(results, s.row())
	}
	return results, nil
}

func generateAIAgentSessionMessages(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	started := time.Now()

	users := discoverUsers()
	filter := newMessageFilter(queryContext)
	messages := collectMessages(users, cutoffTime(started, *maxAgeDays), filter, *maxRows, *maxContentBytes)

	if *verbose {
		log.Printf("ai_agent_session_messages: scanned %d home directories, returned %d messages in %s",
			len(users), len(messages), time.Since(started).Round(time.Millisecond))
	}
	if *maxRows > 0 && len(messages) == *maxRows {
		// Never let a capped result read as a complete one.
		log.Printf("ai_agent_session_messages: result truncated at the --max-rows limit of %d; "+
			"narrow the query with session_id/agent/username or raise the limit", *maxRows)
	}

	results := make([]map[string]string, 0, len(messages))
	for _, m := range messages {
		results = append(results, m.row())
	}
	return results, nil
}

// collectSessions runs every agent collector against every user, newest
// session first.
func collectSessions(users []userHome, cutoff time.Time) []Session {
	var sessions []Session
	for _, u := range users {
		for _, collect := range collectors {
			sessions = append(sessions, collect(u, cutoff)...)
		}
	}

	sort.SliceStable(sessions, func(i, j int) bool {
		if !sessions[i].EndedAt.Equal(sessions[j].EndedAt) {
			return sessions[i].EndedAt.After(sessions[j].EndedAt)
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	return sessions
}

// cutoffTime is the oldest last-write time a transcript may have and still be
// reported. A non-positive maxAge disables the limit.
func cutoffTime(now time.Time, maxAgeDays int) time.Time {
	if maxAgeDays <= 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -maxAgeDays)
}
