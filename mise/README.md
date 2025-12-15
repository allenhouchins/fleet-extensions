# Mise Extension

An osquery extension that exposes tools installed by the `mise` version manager as a native table.

## Overview

This extension creates a `mise_installs` table that contains information about all tools installed by `mise`, including tool name, version, install path, and install time.

## Table Schema

The `mise_installs` table has the following columns:

| Column Name  | Type  | Description                                 |
|-------------|-------|---------------------------------------------|
| tool        | TEXT  | Name of the tool (e.g., `go`, `node`)       |
| version     | TEXT  | Installed version of the tool               |
| install_path| TEXT  | Full path where the version is installed    |
| installed_at| BIGINT| Install time as a Unix timestamp (seconds)  |

## Example Queries

### List all mise-installed tools
```sql
SELECT * FROM mise_installs;
```

### Find all installed versions of a specific tool
```sql
SELECT * FROM mise_installs WHERE tool = 'node';
```

### Find the latest installed version per tool
```sql
SELECT tool, MAX(version) as latest_version
FROM mise_installs
GROUP BY tool;
```

### Sort by install time
```sql
SELECT tool, version, datetime(installed_at, 'unixepoch') as installed_at
FROM mise_installs
ORDER BY installed_at DESC;
```

## Requirements

- macOS or Linux system with [`mise`](https://github.com/jdx/mise) installed
- osquery extension support
- The extension typically runs as root (osqueryd/Fleet), but it reads from the calling user's `mise` data directory layout.

## Installation

### Build the extension
```bash
make build
```

### Install dependencies
```bash
make deps
```

## Usage

### With osqueryi (for testing)
```bash
make dev
```

Then in osqueryi:
```sql
SELECT * FROM mise_installs;
```

### With Fleet
1. Build the extension: `make build`
2. Deploy the `mise.ext` file (and arch-specific binaries if needed) to your Fleet-managed hosts
3. Configure Fleet to load the extension
4. Run queries against the `mise_installs` table

## How It Works

1. **Installs path resolution**:
   - Checks `$MISE_DATA_DIR/installs` if set
   - Falls back to `$XDG_DATA_HOME/mise/installs` if set
   - Defaults to `~/.local/share/mise/installs`
2. **Directory traversal**:
   - Enumerates tool directories (e.g., `go`, `node`, `python`)
   - Under each tool, enumerates version directories (e.g., `1.21.0`, `20.10.0`)
3. **Data collection**:
   - Builds rows with `tool`, `version`, `install_path`, and `installed_at` from the version directory's modification time.
4. **Graceful behavior**:
   - If the installs directory does not exist, returns an empty result instead of an error.

## Error Handling

- If the installs directory cannot be read, the extension returns an empty result.
- Non-directory entries under the installs path are ignored.
- Per-version directory errors are skipped without failing the whole table.

## Development

### Prerequisites
- Go 1.21 or later
- `mise` installed and initialized for the user you are testing as

### Building
```bash
# Install dependencies
make deps

# Build the extension (universal binary and per-arch binaries)
make build

# Run tests
make test

# Clean build artifacts
make clean
```

### Testing
```bash
# Test with osqueryi
make dev
```

## License

This extension is part of the Fleet Extensions project. See the main project LICENSE file for details.


