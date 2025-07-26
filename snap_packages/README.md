# Snap Packages Osquery Extension (Go)

A Go-based osquery extension that provides snap package information as a native table.

## Table Schema

| Column     | Type   | Description                    |
|------------|--------|--------------------------------|
| name       | TEXT   | Snap package name              |
| version    | TEXT   | Package version                |
| rev        | TEXT   | Revision number                |
| tracking   | TEXT   | Tracking channel               |
| publisher  | TEXT   | Package publisher              |
| notes      | TEXT   | Additional notes               |

## Installation

### Automated Installation (Ubuntu)
An automated installation script is provided for Ubuntu systems:
```bash
sudo ./install-snap-packages-extension.sh
```

This script:
- Detects your system architecture (amd64 or arm64)
- Downloads the correct binary from the latest release of `allenhouchins/fleet-extensions`
- Installs it to `/var/fleetd/extensions/`
- Configures osquery to load the extension
- Restarts the orbit service if available

### Manual Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   make deps
   ```
3. Build the extension for both major Linux architectures:
   ```bash
   make build
   ```
   This produces two binaries (both are kept):
   - `snap_packages-amd64.ext` (for x86_64/amd64 Linux)
   - `snap_packages-arm64.ext` (for ARM64 Linux)

   **Choose the binary that matches your system architecture.**

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension snap_packages-<arch>.ext --allow-unsafe
```
Replace `<arch>` with `amd64` or `arm64` as appropriate.

### With standard osquery
```bash
osqueryi --extension=/path/to/snap_packages-<arch>.ext
```

### Example Queries

```sql
-- List all snap packages
SELECT * FROM snap_packages;

-- Find packages by publisher
SELECT * FROM snap_packages WHERE publisher = 'canonical';

-- Check for specific package
SELECT * FROM snap_packages WHERE name = 'docker';

-- Count total packages
SELECT COUNT(*) as total_packages FROM snap_packages;
```

## Structure

```
├── main.go                              # Main extension code
├── install-snap-packages-extension.sh   # Automated installation script
├── go.mod                               # Go module definition
├── Makefile                             # Build configuration
└── README.md                            # This file
```

## Comparison with Shell Script

This Go extension replaces the functionality of `create_snap_database.sh` by:

- **Direct Integration**: No need for SQLite database creation
- **Real-time Data**: Always returns current snap package information
- **Native osquery Table**: Can be queried like any other osquery table
- **Cross-platform**: Works on any Linux system with snap support
- **Performance**: More efficient than shell script + SQLite approach

## Requirements

- Go 1.21 or later
- Linux system with snap support
- osquery or Fleet

## License

Same as the parent project. 