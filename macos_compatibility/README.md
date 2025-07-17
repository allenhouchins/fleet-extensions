# macOS Compatibility Table Osquery Extension (Go)

A Go-based osquery extension that provides a table showing the compatibility of Mac hardware with the latest macOS versions.

## Table Schema

| Column              | Type   | Description                                 |
|---------------------|--------|---------------------------------------------|
| system_version      | TEXT   | Current macOS version                       |
| model_identifier    | TEXT   | Mac model identifier (e.g., MacBookPro16,1) |
| latest_macos        | TEXT   | Latest available macOS version              |
| latest_compatible_macos | TEXT | Latest macOS version compatible with model  |
| is_compatible       | INTEGER| 1 if compatible, 0 if not                   |

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
   - Universal binary: `macos_compatibility.ext` (works on both Intel and Apple Silicon Macs)
   - Architecture-specific binaries: `macos_compatibility-x86_64.ext` (Intel), `macos_compatibility-arm64.ext` (Apple Silicon)

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension macos_compatibility.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/macos_compatibility.ext
```

### Example Queries

```sql
-- List all Mac hardware compatibility
SELECT * FROM macos_compatibility;

-- Find all models compatible with macOS 14
SELECT * FROM macos_compatibility WHERE latest_compatible_macos = '14.0';

-- Check if a specific model is compatible with the latest macOS
SELECT * FROM macos_compatibility WHERE model_identifier = 'MacBookPro16,1';
```

## Structure

```
├── macos_compatibility.go   # Main extension code
├── go.mod                  # Go module definition
├── Makefile                # Build configuration
└── README.md               # This file
```

## Requirements

- Go 1.21 or later
- macOS system
- osquery or Fleet

## License

Same as the parent project.
