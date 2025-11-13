# Ubuntu Pro Extension

Provides Ubuntu Pro (formerly Ubuntu Advantage) status and configuration as a native osquery table.

## Description

This extension exposes Ubuntu Pro subscription information, contract details, and service states (ESM, Livepatch, FIPS, CIS) through the `ubuntu_pro_status` table, enabling you to monitor Ubuntu Pro compliance and contract expiration across your Fleet-managed Ubuntu devices.

## Platforms

- **Linux** (Ubuntu with ubuntu-advantage-tools installed)
- **Binaries:** `ubuntu_pro-amd64.ext`, `ubuntu_pro-arm64.ext`
- **Installation:** Automated install script available for Ubuntu systems

## Table Schema

### ubuntu_pro_status

| Column | Type | Description |
|--------|------|-------------|
| attached | INTEGER | 1 if Ubuntu Pro is attached, 0 if not |
| account_name | TEXT | Ubuntu Pro account name |
| account_id | TEXT | Ubuntu Pro account ID |
| contract_id | TEXT | Contract ID |
| contract_name | TEXT | Contract name (e.g., "Ubuntu Pro") |
| contract_created_at | TEXT | Contract creation timestamp (RFC3339) |
| contract_expires | TEXT | Contract expiration timestamp (RFC3339) |
| days_until_expiration | INTEGER | Days until contract expires (-1 if not attached) |
| version | TEXT | ubuntu-pro-client version |
| esm_infra_status | TEXT | ESM Infrastructure service status |
| esm_infra_entitled | TEXT | ESM Infrastructure entitlement (yes/no) |
| esm_apps_status | TEXT | ESM Applications service status |
| esm_apps_entitled | TEXT | ESM Applications entitlement (yes/no) |
| livepatch_status | TEXT | Livepatch service status |
| livepatch_entitled | TEXT | Livepatch entitlement (yes/no) |
| fips_status | TEXT | FIPS service status |
| fips_entitled | TEXT | FIPS entitlement (yes/no) |
| cis_status | TEXT | CIS service status |
| cis_entitled | TEXT | CIS entitlement (yes/no) |
| error | TEXT | Error message if query failed |

**Service Status Values:** `enabled`, `disabled`, `n/a`
**Entitlement Values:** `yes`, `no`

## Example Queries

### Check if Ubuntu Pro is attached

```sql
SELECT attached FROM ubuntu_pro_status;
```

### Get contract expiration information

```sql
SELECT
  contract_name,
  contract_expires,
  days_until_expiration
FROM ubuntu_pro_status
WHERE attached = 1;
```

### Check service statuses

```sql
SELECT
  esm_infra_status,
  esm_apps_status,
  livepatch_status,
  fips_status
FROM ubuntu_pro_status;
```

### Alert on expiring contracts (< 30 days)

```sql
SELECT
  contract_name,
  contract_expires,
  days_until_expiration
FROM ubuntu_pro_status
WHERE days_until_expiration < 30
  AND days_until_expiration > 0;
```

### Compliance check

```sql
SELECT
  attached,
  esm_infra_status = 'enabled' AS esm_compliant,
  livepatch_status = 'enabled' AS livepatch_compliant
FROM ubuntu_pro_status;
```

## Fleet Integration

Use with Fleet to monitor Ubuntu Pro across your entire fleet:

```sql
SELECT
  h.hostname,
  p.attached,
  p.contract_expires,
  p.days_until_expiration,
  p.esm_infra_status,
  p.livepatch_status
FROM system_info h
JOIN ubuntu_pro_status p;
```

## Installation

### Automated Installation (Fleet)

Use the included `install-ubuntu-pro-extension.sh` script via Fleet's script execution:

```bash
sudo ./install-ubuntu-pro-extension.sh
```

The script will:
1. Detect your Ubuntu architecture (amd64/arm64)
2. Download the correct binary from GitHub releases
3. Install to `/var/fleetd/extensions/`
4. Configure osquery to load the extension
5. Restart Orbit/osquery

### Manual Installation

```bash
# Download the appropriate binary for your architecture
# For amd64:
curl -L -o ubuntu_pro-amd64.ext https://github.com/allenhouchins/fleet-extensions/releases/latest/download/ubuntu_pro-amd64.ext

# Install
sudo mkdir -p /var/fleetd/extensions
sudo mv ubuntu_pro-amd64.ext /var/fleetd/extensions/
sudo chmod 755 /var/fleetd/extensions/ubuntu_pro-amd64.ext

# Configure osquery
echo "/var/fleetd/extensions/ubuntu_pro-amd64.ext" | sudo tee -a /etc/osquery/extensions.load

# Restart orbit
sudo systemctl restart orbit
```

### Testing with osquery

```bash
# Test the extension
sudo orbit shell -- --extension /var/fleetd/extensions/ubuntu_pro-amd64.ext --allow-unsafe

# In the osquery shell:
osquery> SELECT * FROM ubuntu_pro_status;
```

## Building from Source

```bash
cd ubuntu_pro

# Install dependencies
make deps

# Build for all architectures
make build

# Builds:
# - ubuntu_pro-amd64.ext (for x86_64 Ubuntu)
# - ubuntu_pro-arm64.ext (for ARM64 Ubuntu)
```

## Requirements

- **Ubuntu** (any version supported by ubuntu-advantage-tools)
- **ubuntu-advantage-tools** package installed
- **osquery** or **Fleet (Orbit)** installed

To install ubuntu-advantage-tools:
```bash
sudo apt update
sudo apt install ubuntu-advantage-tools
```

## Use Cases

- **Contract Compliance:** Track Ubuntu Pro subscriptions across your fleet
- **Expiration Alerts:** Get notified before contracts expire
- **Security Posture:** Monitor ESM and Livepatch enablement
- **FIPS Compliance:** Track FIPS-enabled systems
- **Inventory:** Maintain accurate records of Ubuntu Pro usage

## Troubleshooting

### Extension returns "pro command not found"

Install ubuntu-advantage-tools:
```bash
sudo apt install ubuntu-advantage-tools
```

### Extension not loading

Check osquery logs:
```bash
sudo journalctl -u orbit -n 50
```

Verify the extension file:
```bash
ls -la /var/fleetd/extensions/ubuntu_pro-*.ext
```

Check extensions.load:
```bash
cat /etc/osquery/extensions.load
```

### Empty results or errors

Test the pro command manually:
```bash
pro status --format json | jq '.'
```

If not attached, the table will show `attached=0` and most fields will be empty.

## License

This extension is part of the fleet-extensions project. See the repository LICENSE for details.
