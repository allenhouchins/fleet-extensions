# Santa Osquery Extension (Go)

A Go-based osquery extension that provides access to Santa binary authorization rules and decision logs as native tables.

## Table Schemas

### santa_rules
| Column         | Type   | Description                                 |
|---------------|--------|---------------------------------------------|
| identifier    | TEXT   | Rule identifier (SHA256, Team ID, etc.)     |
| type          | TEXT   | Type of rule (Binary, Certificate, TeamID)  |
| state         | TEXT   | Rule state (Whitelist, Blacklist)           |
| custom_message| TEXT   | Custom message associated with the rule      |

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