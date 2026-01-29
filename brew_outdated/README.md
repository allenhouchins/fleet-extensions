# brew_outdated Osquery Extension

An osquery extension that provides information about outdated Homebrew packages on macOS systems.

## Overview

This table returns information about Homebrew packages that have updates available. Data returned from the `brew outdated` command. Includes both formula and casks.

## Table Schema

| Column Name | Type | Description |
|--------|------|-------------|
| `name` | TEXT | The name of the Homebrew package |
| `installed_version` | TEXT | The currently installed version |
| `latest_version` | TEXT | The latest available version |

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
   - Universal binary: `brew_outdated.ext` (works on both Intel and Apple Silicon Macs)
   - Architecture-specific binaries: `brew_outdated-x86_64.ext` (Intel), `brew_outdated-arm64.ext` (Apple Silicon)

## Requirements

- Go 1.21 or later
- macOS with Homebrew installed
- osquery or Fleet

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension brew_outdated.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/brew_outdated.ext
```

### Example Queries

Get all outdated packages:
```sql
SELECT * FROM brew_outdated;
```

Count how many outdated packages are installed:
```sql
SELECT COUNT(*) as outdated_count FROM brew_outdated;
```

Find packages with major version updates available:
```sql
SELECT 
  name,
  installed_version,
  latest_version
FROM brew_outdated
WHERE CAST(SUBSTR(latest_version, 1, INSTR(latest_version, '.') - 1) AS INTEGER) > 
      CAST(SUBSTR(installed_version, 1, INSTR(installed_version, '.') - 1) AS INTEGER);
```

Check if a specific package is outdated:
```sql
SELECT * FROM brew_outdated WHERE name = 'curl';
```

## Notes & Limitations

- The extension executes `brew outdated` to get the list of packages with available updates
- If a package has multiple versions installed, a separate row is returned for each installed version
- The extension sets `HOMEBREW_NO_AUTO_UPDATE=1` and `HOMEBREW_NO_ANALYTICS=1` to prevent brew from auto-updating itself or sending analytics
- The table only returns packages that have updates available, so presence in this table indicates the package is outdated. Initially I started with logic to have column for 'outdated = 1' which seemed reduntant. Removed for now but if this is helpful for policy logic, let me know.

## Fleet-Specific Notes

When running in Fleet, osqueryd typically runs as root. Since Homebrew refuses to run as root, the extension uses `sudo -u` to run `brew outdated` as the user who owns the Homebrew installation. When running as root, `sudo -u` works without requiring a password or special sudoers configuration.

**Troubleshooting in Fleet:**
- If the table returns empty results, check Fleet/osquery logs for messages starting with `brew_outdated:`
- The extension logs errors to help diagnose issues

## License

Same as the parent project.
