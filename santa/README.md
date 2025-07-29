# Santa Osquery Extension (Go)

A Go-based osquery extension that provides access to Santa binary authorization rules and decision logs as native tables.

## Table Schemas

### santa_rules
| Column         | Type   | Description                                 |
|---------------|--------|---------------------------------------------|
| identifier    | TEXT   | Rule identifier (SHA256, Team ID, etc.)     |
| type          | TEXT   | Type of rule (Binary, Certificate, TeamID)  |
| state         | TEXT   | Rule state (Allowlist, Blocklist)           |
| custom_message| TEXT   | Custom message associated with the rule      |

> **Note:** The extension uses inclusive terminology ("Allowlist", "Blocklist") in all output, but maintains backward compatibility with legacy terminology internally.

### santa_allowed
| Column      | Type   | Description                       |
|------------|--------|-----------------------------------|
| timestamp  | TEXT   | Timestamp of the decision         |
| application| TEXT   | Path to the application           |
| reason     | TEXT   | Reason for the decision           |
| sha256     | TEXT   | SHA256 hash of the binary         |

### santa_denied
| Column      | Type   | Description                       |
|------------|--------|-----------------------------------|
| timestamp  | TEXT   | Timestamp of the decision         |
| application| TEXT   | Path to the application           |
| reason     | TEXT   | Reason for the decision           |
| sha256     | TEXT   | SHA256 hash of the binary         |

### santa_status
| Column                      | Type    | Description                                                      |
|-----------------------------|---------|------------------------------------------------------------------|
| last_successful_rule        | TEXT    | Last successful rule sync                                        |
| push_notifications          | TEXT    | Push notifications status                                        |
| bundle_scanning             | INTEGER | Whether bundle scanning is enabled (1=true, 0=false)             |
| clean_required              | INTEGER | Whether a clean is required (1=true, 0=false)                    |
| server                      | TEXT    | Sync server address                                              |
| last_successful_full        | TEXT    | Last successful full sync                                        |
| file_logging                | INTEGER | File logging enabled (1=true, 0=false)                           |
| watchdog_ram_events         | INTEGER | Number of watchdog RAM events                                    |
| driver_connected            | INTEGER | Whether the driver is connected (1=true, 0=false)                |
| log_type                    | TEXT    | Log type (e.g., file)                                            |
| watchdog_cpu_events         | INTEGER | Number of watchdog CPU events                                    |
| mode                        | TEXT    | Santa mode (e.g., Monitor)                                       |
| watchdog_cpu_peak           | DOUBLE  | Peak CPU usage                                                   |
| watchdog_ram_peak           | DOUBLE  | Peak RAM usage                                                   |
| transitive_rules_enabled    | INTEGER | Transitive rules enabled (1=true, 0=false)                       |
| remount_usb_mode            | TEXT    | Remount USB mode                                                 |
| block_usb                   | INTEGER | Block USB enabled (1=true, 0=false)                              |
| on_start_usb_options        | TEXT    | USB options on start                                             |
| root_cache_count            | INTEGER | Root cache count                                                 |
| non_root_cache_count        | INTEGER | Non-root cache count                                             |
| static_rule_count           | INTEGER | Static rule count                                                |
| certificate_rules           | INTEGER | Certificate rules count                                          |
| cdhash_rules                | INTEGER | CDHash rules count                                               |
| transitive_rules_count      | INTEGER | Transitive rules count                                           |
| teamid_rules                | INTEGER | Team ID rules count                                              |
| signingid_rules             | INTEGER | Signing ID rules count                                           |
| compiler_rules              | INTEGER | Compiler rules count                                             |
| binary_rules                | INTEGER | Binary rules count                                               |
| events_pending_upload       | INTEGER | Events pending upload                                            |
| watch_items_enabled         | INTEGER | Watch items enabled (1=true, 0=false)                            |

The `santa_status` table exposes the output of `santactl status --json` as an osquery table, allowing you to query Santa's current status and statistics directly from osquery.

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
   - Universal binary: `santa.ext` (works on both Intel and Apple Silicon Macs)
   - Architecture-specific binaries: `santa-x86_64.ext` (Intel), `santa-arm64.ext` (Apple Silicon)

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension santa.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/santa.ext
```

### Example Queries

```sql
-- List all Santa rules
SELECT * FROM santa_rules;

-- List all allowed decisions
SELECT * FROM santa_allowed;

-- List all denied decisions
SELECT * FROM santa_denied;

-- Find all denied binaries for a specific application
SELECT * FROM santa_denied WHERE application LIKE '%Xcode%';

-- Count total denied decisions
SELECT COUNT(*) as total_denied FROM santa_denied;

-- Get current Santa status
SELECT * FROM santa_status;
```

## Structure

```
├── main.go              # Main extension code
├── santa_log.go         # Santa log parsing
├── santa_rules.go       # Santa rules table
├── santa.go             # Table registration and helpers
├── go.mod               # Go module definition
├── Makefile             # Build configuration
└── README.md            # This file
```

## Requirements

- Go 1.21 or later
- macOS with Santa installed
- osquery or Fleet

## Notes & Limitations

- The extension can read Santa rules and decisions, but modifying rules through the extension is limited due to Santa's database locking.
- Requires appropriate permissions to access Santa's database and log files.

## License

Same as the parent project. 