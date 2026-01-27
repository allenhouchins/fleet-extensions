# Local Network Permissions Extension

An osquery extension that exposes macOS Local Network Privacy permissions as a queryable table.

## Overview

On macOS, the Local Network Privacy feature (introduced in macOS Big Sur) controls which applications can discover and communicate with devices on the local network. This extension reads the permission data from the system's NetworkExtension plist and exposes it as an osquery table.

## Platform

- **macOS only** (requires access to `/Library/Preferences/com.apple.networkextension.plist`)

## Table Schema

```sql
CREATE TABLE local_network_permissions (
    bundle_id TEXT,        -- Application bundle identifier (e.g., "com.docker.docker")
    executable_path TEXT,  -- Path to the executable
    display_name TEXT,     -- User-visible application name
    type TEXT,             -- Entry type (typically "applications")
    state INTEGER,         -- Permission state (1 = allowed)
    provider_added TEXT    -- Whether provider was added ("YES" or "")
);
```

## Example Queries

### List all applications with local network access

```sql
SELECT display_name, bundle_id, executable_path 
FROM local_network_permissions 
ORDER BY display_name;
```

### Find non-Apple applications with local network access

```sql
SELECT display_name, bundle_id, executable_path
FROM local_network_permissions
WHERE bundle_id NOT LIKE 'com.apple.%'
ORDER BY display_name;
```

### Find applications installed outside /Applications or /System

```sql
SELECT display_name, bundle_id, executable_path
FROM local_network_permissions
WHERE executable_path NOT LIKE '/Applications/%'
  AND executable_path NOT LIKE '/System/%'
ORDER BY display_name;
```

### Count permissions by type

```sql
SELECT type, COUNT(*) as count
FROM local_network_permissions
GROUP BY type;
```

## Building

```bash
# Install dependencies
make deps

# Build universal binary (Intel + Apple Silicon)
make build

# Clean build artifacts
make clean
```

## Testing

```bash
# Run with osquery (requires sudo for reading system plist)
sudo osqueryi --extension=./local_network_permissions.ext

# Then query the table
osquery> SELECT * FROM local_network_permissions;

# Run with orbit (requires sudo for reading system plist)
sudo /opt/orbit/bin/orbit/orbit shell -- --extension ./local_network_permissions.ext --allow_unsafe

# Then query the table
osquery> SELECT * FROM local_network_permissions;

```


## Technical Details

The extension reads from `/Library/Preferences/com.apple.networkextension.plist`, which is an NSKeyedArchiver-encoded binary plist. The decoder:

1. Parses the binary plist format
2. Resolves CF$UID references in the NSKeyedArchiver object graph
3. Extracts application permission entries
4. Maps fields to the table schema

## Requirements

- macOS (tested on macOS 26)
- Access permissions to read the system plist file
- osquery installed on the system

## License

Same as the parent project.
