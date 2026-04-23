# SentinelOne osquery Extension

Provides endpoint security status and threat intelligence data from SentinelOne agents through osquery tables.

## Supported Platforms

- ✅ **Windows** - Via `SentinelCtl.exe`
- ✅ **macOS** - Via `sentinelctl`
- ⏳ **Linux** - Planned for future release

## Table Schema

### `sentinelone_info`

Exposes SentinelOne agent status, version, and threat information.

| Column | Type | Description | Platforms |
|--------|------|-------------|-----------|
| `agent_id` | TEXT | Unique agent UUID/identifier | macOS |
| `agent_version` | TEXT | SentinelOne agent version | All |
| `agent_loaded` | TEXT | Whether agent is loaded ("true"/"false") | All |
| `monitor_loaded` | TEXT | Whether monitor is loaded ("true"/"false") | Windows |
| `protection_status` | TEXT | Protection enabled status ("On"/"Off") | All |
| `infected_status` | TEXT | Threat detection status | macOS |
| `self_protection_status` | TEXT | Tamper protection status ("On"/"Off") | Windows, macOS |
| `network_quarantine_status` | TEXT | Network quarantine state | macOS |
| `install_date` | TEXT | Agent installation date | macOS |
| `es_framework_status` | TEXT | Endpoint Security framework status | macOS |
| `fw_extension_status` | TEXT | Firewall extension status | macOS |

**Note:** Some fields are platform-specific and will be empty on unsupported platforms.

## Example Queries

### Basic Agent Information
```sql
SELECT * FROM sentinelone_info;
```

### Check Protection Status
```sql
SELECT
    agent_id,
    agent_version,
    protection_status,
    agent_loaded
FROM sentinelone_info
WHERE protection_status = 'On';
```

### Find Infected Systems
```sql
SELECT
    agent_id,
    infected_status,
    agent_version,
    network_quarantine_status
FROM sentinelone_info
WHERE infected_status != 'Not Infected'
   OR infected_status != '';
```

### Verify Agent is Running (Windows)
```sql
SELECT
    agent_version,
    agent_loaded,
    monitor_loaded,
    self_protection_status
FROM sentinelone_info
WHERE agent_loaded = 'true'
  AND monitor_loaded = 'true';
```

### macOS Endpoint Security Status
```sql
SELECT
    agent_id,
    agent_version,
    es_framework_status,
    fw_extension_status,
    protection_status
FROM sentinelone_info
WHERE es_framework_status != 'Running';
```

### Agent Version Compliance Check
```sql
-- Check for agents below minimum version
SELECT
    agent_id,
    agent_version,
    protection_status
FROM sentinelone_info
WHERE CAST(
    SUBSTR(agent_version, 1, INSTR(agent_version, '.') - 1)
    AS INTEGER
) < 22;
```

## Requirements

### Privileges

- **Windows:** Requires Administrator privileges
- **macOS:** Requires elevated privileges or Full Disk Access
- **Note:** osquery typically runs with appropriate privileges, but verify in restrictive environments

### SentinelOne Agent

The SentinelOne agent must be installed at the following locations:

- **Windows:** `C:\Program Files\SentinelOne\Sentinel Agent <Version>\SentinelCtl.exe`
- **macOS:** `/usr/local/bin/sentinelctl` or `/opt/sentinelone/bin/sentinelctl`

## Behavior

### Graceful Degradation

The extension handles missing or inaccessible agents gracefully:

- **Agent not installed:** Returns empty result set (no rows)
- **Permission denied:** Returns empty result set with logged warning
- **Partial data:** Returns available fields, empty strings for missing optional data
- **Critical fields missing:** Returns empty result set

### Critical Fields

The following fields are required for a row to be returned:
- `agent_version` - Identifies the agent version
- `protection_status` - Core security indicator

If these fields cannot be parsed, the table returns an empty result.

## Platform-Specific Notes

### Windows

- Agent ID is not available from status output (future: registry lookup)
- Version is extracted from "Monitor Build id" field
- Uses glob pattern to find versioned installation directory
- Protection status inferred from agent loaded state

### macOS

- Agent ID comes from UUID in status output
- Agent loaded status inferred from ES Framework state
- Multiple installation paths checked in priority order
- Rich threat and quarantine status available

### Linux

Linux support is planned for a future release. Currently returns empty result with log message.

## Testing

Run unit tests:
```bash
go test ./tables/sentinelone/... -v
```

## Troubleshooting

### Empty Results

If the table returns no rows:

1. **Verify agent is installed:**
   - Windows: Check `C:\Program Files\SentinelOne\`
   - macOS: Run `which sentinelctl`

2. **Check permissions:**
   - Windows: Ensure osquery runs with Administrator privileges
   - macOS: Verify Full Disk Access for osquery process

3. **Test sentinelctl manually:**
   - Windows: `SentinelCtl.exe status`
   - macOS: `sentinelctl status`

4. **Check logs:**
   - Permission denied messages indicate privilege issues
   - "Not found" messages indicate agent not installed

### Partial Data

Some fields may be empty even when the agent is installed:

- **agent_id on Windows:** Not available from CLI (known limitation)
- **install_date on Windows:** Not available from CLI (future enhancement)
- **monitor_loaded on macOS:** Not exposed in status output

## Implementation Details

- **Language:** Go
- **Dependencies:** osquery-go, pkg/errors
- **Build System:** Bazel
- **Test Coverage:** 15 test cases covering Windows, macOS, parsing, and error handling

## Related Extensions

- `crowdstrike_falcon` - CrowdStrike Falcon agent status

## License

Same as parent osquery-extension project.
