# AI Agent Sessions Osquery Extension

An osquery extension that reports the AI coding agent session history stored on a host, as native osquery tables.

## Overview

AI coding agents keep a local record of every session they run. This extension reads those records and exposes two tables:

| Table | Grain | Contains conversation text |
|-------|-------|----------------------------|
| [`ai_agent_sessions`](#ai_agent_sessions) | One row per session | **No** |
| [`ai_agent_session_messages`](#ai_agent_session_messages) | One row per content block | **Yes** |

`ai_agent_sessions` answers which agents are in use across the fleet, which repositories they are being pointed at, which models they are calling, and how much they are being used. It is the table to schedule.

`ai_agent_session_messages` returns the actual conversation — prompts, replies, model reasoning, tool calls and their arguments, and tool output. It is the table to query on demand against a specific session.

### Choosing between them

`ai_agent_sessions` reads message *shapes* rather than message content: prompt and response text is skipped by the JSON decoder and never enters memory. Source code, credentials, and anything else a developer typed into an agent stays on the host.

`ai_agent_session_messages` does the opposite by design, and that has consequences worth being deliberate about:

- **Query results leave the host.** Under Fleet, rows go to the server and are retained there. A conversation transcript is very likely to contain source code, file contents, internal hostnames, and whatever a developer pasted into a prompt — including secrets they did not mean to paste.
- **It is unbounded without limits**, so it ships with them. By default a query returns at most 5,000 rows and truncates each block to 8 KB, and the extension logs a warning when a result hits the row cap so a capped result never reads as a complete one. Both limits are configurable, including off.
- **Scope your queries.** Equality constraints on `session_id`, `agent`, `username`, and `transcript_path` are pushed down, so a query filtered on `session_id` reads only that transcript. The intended workflow is to find sessions of interest in `ai_agent_sessions`, then pull the content for those specific `session_id`s.

Scheduling an unconstrained `SELECT * FROM ai_agent_session_messages` across a fleet is the thing to avoid; everything else is a reasonable use.

## Supported agents

| `agent` value | Source | Verified against real data |
|---------------|--------|----------------------------|
| `claude_code` | `~/.claude/projects/<project>/<session-id>.jsonl` | Yes |
| `copilot_cli` | `~/.copilot/session-state/<session-id>/events.jsonl` | Yes |
| `cursor` | `~/.cursor/projects/<project>/agent-transcripts/<session-id>/<session-id>.jsonl` | Yes |
| `codex_cli` | `~/.codex/sessions/**/rollout-*.jsonl` | **No** — see below |
| `gemini_cli` | `~/.gemini/tmp/<project-hash>/logs.json` | **No** — see below |

The Claude Code, Copilot CLI, and Cursor parsers were written against real on-disk transcripts and their counts cross-checked against an independent parser. The Codex CLI and Gemini CLI parsers were written against those tools' documented rollout and log formats but **no host with Codex or Gemini session data was available to test them**. They are defensive — an unrecognized record is skipped rather than failing the session — but treat their output as unverified until you have confirmed it on a host that runs those agents.

## `ai_agent_sessions`

| Column Name | Type | Description |
|-------------|------|-------------|
| `agent` | TEXT | Which agent produced the session (see the table above) |
| `session_id` | TEXT | The agent's own identifier for the session |
| `username` | TEXT | Local account the session belongs to; joins to `users.username` |
| `project_path` | TEXT | Directory the session was started in |
| `git_branch` | TEXT | Git branch the session ended on |
| `git_repository` | TEXT | Repository the session was working in |
| `agent_version` | TEXT | Version of the agent that ran the session |
| `model` | TEXT | Model that served the session |
| `started_at` | BIGINT | Unix timestamp of the first recorded activity, or `0` if unknown |
| `ended_at` | BIGINT | Unix timestamp of the last recorded activity |
| `duration_seconds` | BIGINT | Wall-clock span of the session, or `0` if either end is unknown |
| `user_messages` | BIGINT | Prompts the person typed, excluding tool results fed back to the model |
| `assistant_messages` | BIGINT | Turns the model produced |
| `tool_calls` | BIGINT | Tools the model invoked |
| `input_tokens` | BIGINT | Uncached input tokens |
| `output_tokens` | BIGINT | Output tokens |
| `cache_read_tokens` | BIGINT | Tokens served from the prompt cache |
| `cache_write_tokens` | BIGINT | Tokens written to the prompt cache |
| `transcript_path` | TEXT | File the metadata was read from |
| `transcript_size_bytes` | BIGINT | Size of that file |

Columns an agent does not record are returned empty (text) or `0` (integer) rather than guessed at. Coverage per agent:

| | claude_code | copilot_cli | cursor | codex_cli | gemini_cli |
|---|---|---|---|---|---|
| `project_path` | ✅ | ✅ | ✅ (see below) | ✅ | ❌ (hashed) |
| `git_branch` | ✅ | ✅ | ❌ | ✅ | ❌ |
| `git_repository` | ❌ | ✅ | ❌ | ✅ | ❌ |
| `agent_version` | ✅ | ✅ | ❌ | ✅ | ❌ |
| `model` | ✅ | ✅ | ❌ | ✅ | ❌ |
| `started_at` | ✅ | ✅ | ❌ | ✅ | ✅ |
| `user_messages` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `assistant_messages` | ✅ | ✅ | ✅ | ✅ | ❌ |
| `tool_calls` | ✅ | ⚠️ | ✅ | ✅ | ❌ |
| token columns | ✅ | ✅ | ❌ | ✅ (no cache write) | ❌ |

⚠️ No Copilot session on the test host invoked a tool, so the event names the tool-call counter matches are inferred rather than observed. A Copilot session that used tools may report `0`.

## `ai_agent_session_messages`

One row per **content block**, not per message. A single assistant turn that says something and then calls two tools produces three rows, which keeps `content` meaningful for each and lets you filter to just the part you want.

| Column Name | Type | Description |
|-------------|------|-------------|
| `agent` | TEXT | Which agent produced the session |
| `session_id` | TEXT | The agent's identifier for the session; joins to `ai_agent_sessions.session_id` |
| `username` | TEXT | Local account the session belongs to |
| `message_index` | BIGINT | Position of the turn within the session, from 0 |
| `block_index` | BIGINT | Position of the block within its turn, from 0 |
| `role` | TEXT | `user`, `assistant`, or `system` |
| `block_type` | TEXT | `text`, `thinking`, `tool_use`, or `tool_result` |
| `tool_name` | TEXT | Tool invoked, on `tool_use` and `tool_result` rows |
| `timestamp` | BIGINT | Unix timestamp of the turn, or `0` if the agent records none |
| `model` | TEXT | Model that produced the turn, on assistant rows |
| `content` | TEXT | The block's text; for `tool_use` this is the JSON arguments the agent sent |
| `content_length` | BIGINT | Length of the content **before** truncation |
| `truncated` | INTEGER | `1` when `content` was cut to `--max-content-bytes` |
| `transcript_path` | TEXT | File the row was read from |

Roles follow what actually happened rather than the on-disk encoding. Agents record tool output as a "user" turn, because that is how it is fed back to the model; here those rows are `role = 'system'`, so `role = 'user'` means a person typed it.

Per-agent coverage:

| | claude_code | copilot_cli | cursor | codex_cli | gemini_cli |
|---|---|---|---|---|---|
| user / assistant text | ✅ | ✅ | ✅ | ✅ | user only |
| `thinking` blocks | ✅ | ❌ | ❌ | ✅ | ❌ |
| `tool_use` with arguments | ✅ | ⚠️ | ✅ | ✅ | ❌ |
| `tool_result` | ✅ | ⚠️ | ✅ | ✅ | ❌ |
| `timestamp` | ✅ | ✅ | ❌ | ✅ | ✅ |
| `model` | ✅ | ✅ | ❌ | ✅ | ❌ |

⚠️ As with the tool-call counter, Copilot's tool event names are inferred rather than observed.

## Building the Extension

1. Clone the repository
2. Install dependencies:
   ```bash
   make deps
   ```
3. Build the extension:
   ```bash
   make build
   ```
   This produces:
   - Universal macOS binary: `ai_agent_sessions.ext` (Intel and Apple Silicon)
   - macOS: `ai_agent_sessions-x86_64.ext`, `ai_agent_sessions-arm64.ext`
   - Linux: `ai_agent_sessions-amd64.ext`, `ai_agent_sessions-linux-arm64.ext`
   - Windows: `ai_agent_sessions-amd64.exe`, `ai_agent_sessions-arm64.exe`

`make macos`, `make linux`, and `make windows` build a single platform. The macOS universal binary requires `lipo`, so `make build` needs to run on macOS; use the per-platform targets elsewhere.

## Requirements

- Go 1.26 or later
- macOS, Linux, or Windows
- osquery or Fleet

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension ai_agent_sessions.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/ai_agent_sessions.ext
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--max-age-days` | `30` | Only report sessions whose transcript was last written within this many days. Set to `0` for all history. Applies to both tables. |
| `--max-rows` | `5000` | Maximum `ai_agent_session_messages` rows per query, filled newest transcript first. Set to `0` for no limit. |
| `--max-content-bytes` | `8192` | Truncate each `ai_agent_session_messages` block to this many bytes, never mid-character. The `truncated` column flags affected rows and `content_length` keeps the original size. Set to `0` for no limit. |
| `--verbose` | off | Log the home directory count, row count, and scan duration to stderr on each query. osquery passes this flag to autoloaded extensions when it is itself running verbose, so the extension must accept it or it would exit at flag parsing and never register the tables. |

The default keeps scheduled queries cheap on hosts with a long agent history. Raise or disable it when you need a longer window:

```bash
osqueryi --extension=/path/to/ai_agent_sessions.ext --extensions_args="--max-age-days=0"
```

## Example queries and policies

Which agents are in use on this host, and how heavily:
```sql
SELECT agent, COUNT(*) AS sessions, SUM(user_messages) AS prompts, SUM(output_tokens) AS output_tokens
FROM ai_agent_sessions
GROUP BY agent
ORDER BY sessions DESC;
```

Which repositories agents have been pointed at:
```sql
SELECT project_path, agent, COUNT(*) AS sessions, MAX(ended_at) AS last_used
FROM ai_agent_sessions
GROUP BY project_path, agent
ORDER BY last_used DESC;
```

Which models are being called:
```sql
SELECT model, COUNT(*) AS sessions
FROM ai_agent_sessions
WHERE model != ''
GROUP BY model
ORDER BY sessions DESC;
```

Sessions in the last seven days, newest first:
```sql
SELECT agent, username, project_path, git_branch, model, datetime(ended_at, 'unixepoch') AS ended
FROM ai_agent_sessions
WHERE ended_at > (strftime('%s', 'now') - 604800)
ORDER BY ended_at DESC;
```

Join session activity to the local account that ran it:
```sql
SELECT s.agent, s.session_id, u.username, u.directory, s.project_path
FROM ai_agent_sessions s
JOIN users u ON u.username = s.username;
```

Policy — the host has used an AI coding agent in the last 30 days:
```sql
SELECT 1 FROM ai_agent_sessions LIMIT 1;
```

Policy — no agent session has run against a repository outside the approved directory:
```sql
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM ai_agent_sessions
  WHERE project_path != '' AND project_path NOT LIKE '/Users/%/GitHub/%'
);
```

### Session content

Read one session end to end, in order — the constraint on `session_id` means only that transcript is opened:
```sql
SELECT message_index, block_index, role, block_type, tool_name, content
FROM ai_agent_session_messages
WHERE session_id = '5d1f26db-93ed-4161-9cd9-3eafded86d89'
ORDER BY message_index, block_index;
```

Just the prompts a person typed, most recent first:
```sql
SELECT username, session_id, datetime(timestamp, 'unixepoch') AS at, content
FROM ai_agent_session_messages
WHERE role = 'user' AND block_type = 'text'
ORDER BY timestamp DESC;
```

Which commands agents actually ran, and with what arguments:
```sql
SELECT tool_name, COUNT(*) AS calls
FROM ai_agent_session_messages
WHERE block_type = 'tool_use'
GROUP BY tool_name
ORDER BY calls DESC;
```

```sql
SELECT session_id, datetime(timestamp, 'unixepoch') AS at, content AS arguments
FROM ai_agent_session_messages
WHERE block_type = 'tool_use' AND tool_name = 'Bash'
ORDER BY timestamp DESC;
```

Pull the content for the sessions a metadata query identified:
```sql
SELECT m.session_id, m.role, m.content
FROM ai_agent_session_messages m
JOIN ai_agent_sessions s ON s.session_id = m.session_id
WHERE s.project_path LIKE '%/fleet' AND m.role = 'user' AND m.block_type = 'text';
```

Find prompts that mention something you care about:
```sql
SELECT username, session_id, datetime(timestamp, 'unixepoch') AS at, content
FROM ai_agent_session_messages
WHERE role = 'user' AND content LIKE '%password%';
```

Check whether a result was cut short before trusting a count:
```sql
SELECT COUNT(*) AS rows_returned, SUM(truncated) AS truncated_blocks
FROM ai_agent_session_messages;
```

## Notes & Limitations

- **`ai_agent_sessions` is metadata only.** No column in that table is derived from prompt or response text; message bodies are skipped by the JSON decoder rather than read and discarded. `ai_agent_session_messages` is the opposite by design — see [Choosing between them](#choosing-between-them).
- **`ai_agent_session_messages` results are capped by default** at 5,000 rows and 8 KB per block. When a query hits the row cap the extension logs a warning to osquery's log, because a silently capped result would read as a complete one. Constrain on `session_id`, `agent`, `username`, or `transcript_path` to scope a query rather than raising the cap.
- **Rows are filled newest transcript first**, so a capped result is the most recent activity rather than an arbitrary slice of it.
- **Content is truncated on a character boundary**, never mid-rune, so a truncated block is still valid UTF-8.
- **Tool arguments are returned as the raw JSON the agent sent.** That is the most faithful representation, and it is also where file paths and shell commands live.
- **All users are scanned.** Under Fleet, osqueryd runs as root, so the extension enumerates every local home directory rather than only the invoking user's. On macOS it scans `/Users`, on Linux it reads `/etc/passwd` and `/home`, and on Windows it scans the `Users` directory on the system drive. These binaries are built without cgo, so usernames come from the home directory name rather than an `os/user` lookup — which matters on macOS, where local accounts live in OpenDirectory and not in `/etc/passwd`.
- **`user_messages` counts real prompts.** Turns that only carry tool results back to the model are part of the agent loop, not something a person typed, and are excluded.
- **Subagent turns are included** in the message and tool counts of the session that spawned them. They do not get their own rows.
- **Token totals are what the agent recorded**, and the agents do not all account the same way. Claude Code and Copilot report per-request usage that the extension sums or takes from the session total; Codex reports a running cumulative total, so the last value wins. Copilot only writes its totals at shutdown, so a session killed mid-flight reports `0`.
- **Cursor transcripts carry no timestamps, model, or token usage.** `ended_at` falls back to the transcript file's modification time and `started_at` stays `0`.
- **Cursor project paths are reconstructed** from a dash-encoded directory name, which is lossy because directory names may themselves contain dashes. The extension walks the filesystem and prefers the longest segment run that names a real directory, so `Users-alice-GitHub-fleet-extensions` resolves to `/Users/alice/GitHub/fleet-extensions` when that directory exists. If the project has since been deleted or renamed, the naive expansion is returned instead.
- **Gemini CLI identifies projects by an opaque hash** of their path, so `project_path` cannot be recovered. Its log records prompts only, so `assistant_messages`, `tool_calls`, `model`, and the token columns stay at `0`.
- **A deleted transcript is a deleted row.** Agents prune their own history, and the table reflects whatever is on disk right now. This is a picture of local state, not an audit log — a user who clears their agent history clears these rows too.
- Individual records larger than 8 MB are skipped. A transcript line that big is a pasted file or a large tool result, and carries no metadata the table needs.
- Malformed records are skipped rather than discarding the whole session.

## License

Same as the parent project.
