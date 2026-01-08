# Homebrew Info Extension

An osquery extension that provides detailed information about Homebrew packages (formulas and casks) installed on macOS systems. This extension is a Go implementation of the osquery `homebrew_packages` table.

## Overview

This extension creates a `homebrew_info` table that contains comprehensive information about all Homebrew packages installed on the system, including package names, versions, installation paths, package types (cask vs formula), prefixes, auto-update settings, and app names (for casks).

## Table Schema

The `homebrew_info` table has the following columns:

| Column Name | Type | Description |
|-------------|------|-------------|
| name | TEXT | Name of the Homebrew package |
| path | TEXT | Full path to the package directory (Cellar for formulas, Caskroom for casks) |
| version | TEXT | Installed version of the package |
| type | TEXT | Package type: "formula" or "cask" |
| auto_updates | TEXT | For casks: "1" if auto-updates are enabled, "0" otherwise. Empty for formulas. |
| app_name | TEXT | For casks: Name of the installed application (e.g., "iTerm.app"). Empty for formulas. |
| latest_version | TEXT | Latest available version from Homebrew (not the installed version). Empty if unavailable. |
| is_latest | TEXT | "yes" if the installed version matches the latest available version, "no" otherwise. Empty if latest_version is unavailable. |

## Example Queries

### List all installed Homebrew packages
```sql
SELECT * FROM homebrew_info;
```


### List only casks with auto-updates enabled
```sql
SELECT name, version, app_name FROM homebrew_info 
WHERE type = 'cask' AND auto_updates = '1';
```

### List only formulae
```sql
SELECT * FROM homebrew_info WHERE type = 'formula';
```

### Find a specific package
```sql
SELECT * FROM homebrew_info WHERE name = 'git';
```

### Count packages by type
```sql
SELECT type, COUNT(*) as count FROM homebrew_info GROUP BY type;
```

### List all casks with their app names
```sql
SELECT name, version, app_name, prefix FROM homebrew_info 
WHERE type = 'cask' AND app_name != '';
```

### Find packages that are out of date
```sql
SELECT name, version, latest_version, type FROM homebrew_info 
WHERE is_latest = 'no' AND latest_version != '';
```

### List packages that are up to date
```sql
SELECT name, version, latest_version FROM homebrew_info 
WHERE is_latest = 'yes';
```

### List packages with their installed and latest versions
```sql
SELECT name, version, latest_version, is_latest
FROM homebrew_info 
WHERE latest_version != '';
```

## Requirements

- macOS system with Homebrew installed
- osquery extension support
- The extension checks both `/opt/homebrew` (Apple Silicon) and `/usr/local` (Intel) prefixes automatically

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
SELECT * FROM homebrew_info;
```

### With Fleet
1. Build the extension: `make build`
2. Deploy the `homebrew_info.ext` file to your Fleet-managed hosts
3. Configure Fleet to load the extension
4. Run queries against the `homebrew_info` table

## How It Works

The extension implements the same logic as the osquery C++ `homebrew_packages` table (but registers as `homebrew_info` to avoid conflicts):

1. **Prefix Detection**: Automatically checks both `/opt/homebrew` (Apple Silicon) and `/usr/local` (Intel Mac) prefixes
2. **Formula Scanning**: Reads from the `Cellar` directory to discover installed formulas and their versions
3. **Cask Scanning**: Reads from the `Caskroom` directory to discover installed casks and their versions
4. **Metadata Parsing**: For casks, parses metadata files (`.json` or `.rb`) from the `.metadata` directory to extract:
   - `auto_updates`: Whether the cask has auto-updates enabled
   - `app_name`: The name of the installed application (e.g., "iTerm.app")
5. **Version Detection**: Lists all installed versions for each package (Homebrew supports multiple versions)
6. **Latest Version Detection**: Uses `brew info --json=v2` to fetch the latest available version from Homebrew
7. **Caching**: Latest versions are cached for 1 hour to improve performance and reduce API calls
8. **Query Constraints**: Supports filtering by `prefix` in queries

### Metadata File Locations

For casks, metadata files are typically located at:
- `/opt/homebrew/Caskroom/<cask>/.metadata/<version>/<timestamp>/Casks/<cask>.json`
- `/opt/homebrew/Caskroom/<cask>/.metadata/<version>/<timestamp>/Casks/<cask>.rb`

The extension recursively searches the `.metadata` directory to find these files.

## Error Handling

- If a prefix doesn't exist or isn't accessible, the extension logs a warning and continues with other prefixes
- If metadata files cannot be read for a cask, `auto_updates` defaults to "0" and `app_name` is empty
- If `brew info` fails or cannot determine the latest version, `latest_version` will be empty
- The extension gracefully handles missing directories and files
- Latest version lookups are cached for 1 hour to avoid repeated slow API calls

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

## Differences from C++ Implementation

This Go implementation maintains feature parity with the C++ version, including:
- Support for both formulas and casks
- Multiple version detection
- Metadata parsing for casks (auto_updates and app_name)
- Prefix constraint support in queries
- Same default prefixes (`/usr/local` and `/opt/homebrew`)

## Troubleshooting

### Common Issues

1. **Empty results**
   - Verify Homebrew is installed: `brew --version`
   - Check if packages are installed: `brew list`
   - Verify the Cellar or Caskroom directories exist

2. **Missing metadata for casks**
   - Some casks may not have metadata files if they were installed before metadata tracking was added
   - The extension will still return package information, but `auto_updates` and `app_name` will be empty

3. **Permission errors**
   - The extension should run with appropriate permissions to read Homebrew directories
   - Ensure the osquery process has access to `/opt/homebrew` or `/usr/local`

## License

This extension is part of the Fleet Extensions project. See the main project LICENSE file for details.

