# Microsoft Defender Health Osquery Extension

A Go-based osquery extension that provides access to Microsoft Defender health using the `mdatp` binary.

## Overview

This extension creates an `mdatp_status` table that contains comprehensive information about Microsoft Defender for Endpoint's current status, configuration, and health on macOS systems.

mdatp = Microsoft Defender Advanced Threat Protection. More information can be found on [Microsoft's documention.](https://learn.microsoft.com/en-us/defender-endpoint/health-status)

## Table Schema

The `mdatp_status` table has the following columns:

| Column Name | Type | Description |
|-------------|------|-------------|
| healthy | TEXT | Overall health status |
| health_issues | TEXT | Any health issues detected |
| licensed | TEXT | License status |
| engine_version | TEXT | Antivirus engine version |
| engine_load_status | TEXT | Engine load status |
| app_version | TEXT | Application version |
| org_id | TEXT | Organization ID |
| log_level | TEXT | Current log level |
| machine_guid | TEXT | Machine GUID |
| release_ring | TEXT | Release ring (e.g., Production, Insider) |
| product_expiration | TEXT | Product expiration date |
| cloud_enabled | TEXT | Cloud protection enabled status |
| cloud_automatic_sample_submission_consent | TEXT | Automatic sample submission consent |
| cloud_diagnostic_enabled | TEXT | Cloud diagnostic enabled status |
| cloud_pin_certificate_thumbs | TEXT | Pinned certificate thumbprints |
| passive_mode_enabled | TEXT | Passive mode enabled status |
| behavior_monitoring | TEXT | Behavior monitoring status |
| real_time_protection_enabled | TEXT | Real-time protection enabled status |
| real_time_protection_available | TEXT | Real-time protection availability |
| real_time_protection_subsystem | TEXT | Real-time protection subsystem |
| network_events_subsystem | TEXT | Network events subsystem |
| device_control_enforcement_level | TEXT | Device control enforcement level |
| tamper_protection | TEXT | Tamper protection status |
| automatic_definition_update_enabled | TEXT | Automatic definition updates enabled |
| definitions_updated | TEXT | Last definitions update timestamp |
| definitions_updated_minutes_ago | TEXT | Minutes since last definitions update |
| definitions_version | TEXT | Current definitions version |
| definitions_status | TEXT | Definitions status |
| edr_early_preview_enabled | TEXT | EDR early preview enabled |
| edr_device_tags | TEXT | EDR device tags |
| edr_group_ids | TEXT | EDR group IDs |
| edr_configuration_version | TEXT | EDR configuration version |
| edr_machine_id | TEXT | EDR machine ID |
| conflicting_applications | TEXT | Conflicting applications detected |
| network_protection_status | TEXT | Network protection status |
| network_protection_enforcement_level | TEXT | Network protection enforcement level |
| data_loss_prevention_status | TEXT | Data loss prevention status |
| full_disk_access_enabled | TEXT | Full disk access enabled |
| troubleshooting_mode | TEXT | Troubleshooting mode status |
| ecs_configuration_ids | TEXT | ECS configuration IDs |
| error | TEXT | Error message if any occurred |

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
   - Universal binary: `mdatp_extension.ext` (works on both Intel and Apple Silicon Macs)
   - Architecture-specific binaries: `mdatp_extension-x86_64.ext` (Intel), `mdatp_extension-arm64.ext` (Apple Silicon)

## Requirements

- Go 1.21 or later
- macOS with Microsoft Defender for Endpoint installed
- Microsoft Defender CLI (`mdatp`) must be available on host machine at:
  - `/usr/local/bin/mdatp` (default)
  - `/opt/microsoft/mdatp/bin/mdatp` (alternative)
- osquery or Fleet

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension mdatp_extension.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/mdatp_extension.ext
```

### Example Queries

```sql
-- Get full Microsoft Defender status
SELECT * FROM mdatp_status;

-- Check if Defender is healthy
SELECT healthy, health_issues FROM mdatp_status;

-- Check real-time protection status
SELECT real_time_protection_enabled, real_time_protection_available 
FROM mdatp_status;

-- Check definitions status
SELECT definitions_version, definitions_status, definitions_updated 
FROM mdatp_status;

-- Check tamper protection
SELECT tamper_protection FROM mdatp_status;

-- Check for conflicting applications
SELECT conflicting_applications FROM mdatp_status 
WHERE conflicting_applications != '';

-- Check cloud protection status
SELECT cloud_enabled, cloud_automatic_sample_submission_consent 
FROM mdatp_status;

-- Check network protection
SELECT network_protection_status, network_protection_enforcement_level 
FROM mdatp_status;
```


## Development

### Prerequisites
- Go 1.21 or later
- Microsoft Defender for Endpoint installed on macOS

### Building
```bash
# Install dependencies
make deps

# Build the extension
make build

# Clean build artifacts
make clean
```

### Testing
```bash
# Test with osqueryi
make test
```

## Notes & Limitations

- The extension reads status information only; it cannot modify Microsoft Defender configuration
- Requires Microsoft Defender for Endpoint to be installed and running
- Some fields may be empty if not applicable to the current configuration
- If the `mdatp` binary is not found, the extension returns an error in the `error` column

## License

Same as the parent project.