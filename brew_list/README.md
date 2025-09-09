# Brew List Extension

An osquery extension that provides information about Homebrew packages installed on macOS systems.

## Overview

This extension creates a `brew_list` table that contains information about all Homebrew packages installed on the system, including package names, versions, installation paths, and package types (cask vs formula).

## Table Schema

The `brew_list` table has the following columns:

| Column Name | Type | Description |
|-------------|------|-------------|
| package_name | TEXT | Name of the Homebrew package |
| version | TEXT | Installed version of the package |
| install_path | TEXT | Full path where the package is installed |
| type | TEXT | Package type: "cask" or "formula" |

## Example Queries

### List all installed Homebrew packages
```sql
SELECT * FROM brew_list;
```

### Find a specific package
```sql
SELECT * FROM brew_list WHERE package_name = 'git';
```

### Count total packages
```sql
SELECT COUNT(*) as total_packages FROM brew_list;
```

### Find packages with specific version patterns
```sql
SELECT package_name, version FROM brew_list WHERE version LIKE '2.%';
```

### List only casks
```sql
SELECT * FROM brew_list WHERE type = 'cask';
```

### List only formulae
```sql
SELECT * FROM brew_list WHERE type = 'formula';
```

### Count packages by type
```sql
SELECT type, COUNT(*) as count FROM brew_list GROUP BY type;
```

## Requirements

- macOS or Linux system with Homebrew/Linuxbrew installed
- osquery extension support
- The extension runs as root (typical for osqueryd/Fleet deployments)
- Homebrew can be installed in any location (the extension will find it automatically)

## Installation

### Build the extension
```bash
make build
```

### Build for multiple architectures
```bash
make build-all
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
SELECT * FROM brew_list;
```

### With Fleet
1. Build the extension: `make build`
2. Deploy the `brew_list.ext` file to your Fleet-managed hosts
3. Configure Fleet to load the extension
4. Run queries against the `brew_list` table

## How It Works

The extension uses intelligent Homebrew detection and multiple data collection methods:

1. **Dynamic Discovery**: Uses `which brew` to find the actual Homebrew installation path
2. **Comprehensive Fallbacks**: Checks common installation paths:
   - `/opt/homebrew/bin/brew` (Apple Silicon Macs)
   - `/usr/local/bin/brew` (Intel Macs)
   - `/home/linuxbrew/.linuxbrew/bin/brew` (Linux)
3. **Multi-Tier Data Collection**:
   - **Tier 1**: Attempts to read Homebrew's SQLite database directly (most efficient)
   - **Tier 2**: Falls back to `brew list` commands with proper environment setup
   - **Tier 3**: Uses directory-based version detection from symlink targets
4. **Package Type Detection**: Determines if packages are casks or formulae by checking:
   - `/opt/homebrew/Caskroom/<package>` for casks
   - `/opt/homebrew/Cellar/<package>` for formulae
5. **Root Compatibility**: Works reliably even when running as root (typical for osqueryd/Fleet)
6. **Structured Output**: Returns complete package information in a structured table format

## Error Handling

- If Homebrew is not installed or not accessible, the extension will return an error
- If individual package information cannot be retrieved, those packages will be skipped
- The extension gracefully handles missing or inaccessible Homebrew installations

## Development

### Prerequisites
- Go 1.21 or later
- Homebrew installed on macOS

### Building
```bash
# Install dependencies
make deps

# Build the extension
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

## Troubleshooting

### Common Issues

1. **"brew command not found"**
   - The extension automatically detects Homebrew using `which brew` and common paths
   - If still failing, verify Homebrew is installed: `which brew`

2. **Permission errors**
   - The extension should run as root (typical for osqueryd)
   - Ensure the osqueryd process has access to Homebrew

3. **Empty results**
   - Verify Homebrew is working: `brew list`
   - Check if packages are actually installed
   - The extension will return detailed error messages for debugging

4. **Cross-platform compatibility**
   - Works on macOS (both Intel and Apple Silicon)
   - Works on Linux with Linuxbrew
   - Automatically detects installation location

### Debug Mode
The extension will return detailed error messages if the `brew` command fails, helping with troubleshooting.

## License

This extension is part of the Fleet Extensions project. See the main project LICENSE file for details.

