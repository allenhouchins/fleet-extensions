# Ubuntu Pro Extension - Integration Guide

**Created:** November 13, 2025
**Repository:** fleet-extensions by Allen Houchins

---

## What Was Created

Added a new `ubuntu_pro` extension to the fleet-extensions repository following the exact same patterns as existing extensions (snap_packages, macos_compatibility, etc.).

### Files Created

```
fleet-extensions/ubuntu_pro/
├── main.go                              # Extension implementation (matches snap_packages pattern)
├── Makefile                             # Build system (matches repo conventions)
├── go.mod                               # Go dependencies
├── README.md                            # Complete documentation
├── install-ubuntu-pro-extension.sh      # Fleet installer script (based on snap_packages)
└── INTEGRATION.md                       # This file
```

---

## What It Does

Exposes Ubuntu Pro (Ubuntu Advantage) status as a native osquery table named `ubuntu_pro_status` with 20 columns:

**Status & Account:**
- attached, account_name, account_id

**Contract:**
- contract_id, contract_name, contract_created_at, contract_expires, days_until_expiration

**Services (status + entitled for each):**
- ESM Infrastructure
- ESM Applications
- Livepatch
- FIPS
- CIS

**Metadata:**
- version, error

---

## How It Matches Repository Conventions

### 1. Code Structure (matches snap_packages/main.go)

```go
// Same pattern as other extensions
func main() {
    var socketPath string = ":0"
    // Socket path handling (same as others)
    plugin := table.NewPlugin("ubuntu_pro_status", UbuntuProColumns(), UbuntuProGenerate)
    srv, err := osquery.NewExtensionManagerServer("ubuntu_pro", socketPath)
    // ... same server setup pattern
}
```

### 2. Makefile (matches snap_packages/Makefile)

```makefile
# Same targets and patterns
all: ubuntu_pro-amd64.ext ubuntu_pro-arm64.ext

ubuntu_pro-amd64.ext:
	GOARCH=amd64 GOOS=linux go build -o ubuntu_pro-amd64.ext .

ubuntu_pro-arm64.ext:
	GOARCH=arm64 GOOS=linux go build -o ubuntu_pro-arm64.ext .
```

### 3. Installer Script (based on snap_packages installer)

- Same architecture detection logic
- Same directory structure (`/var/fleetd/extensions`)
- Same backup/restore mechanism
- Same error handling pattern
- Same GitHub release download strategy

### 4. README Structure

Matches the exact format of other extension READMEs:
- Description
- Platforms
- Table Schema
- Example Queries
- Installation instructions
- Fleet Integration examples
- Building from Source
- Troubleshooting

---

## Next Steps

### 1. Test the Extension Locally

```bash
cd /Users/mitch/code/clone/fleet-extensions/ubuntu_pro

# Initialize dependencies
make deps

# Build (creates amd64 and arm64 binaries)
make build

# Test on an Ubuntu machine with osquery:
sudo orbit shell -- --extension ubuntu_pro-amd64.ext --allow-unsafe

# In osquery:
osquery> SELECT * FROM ubuntu_pro_status;
```

### 2. Commit to Git

```bash
cd /Users/mitch/code/clone/fleet-extensions

# Check status
git status

# Add the new extension
git add ubuntu_pro/

# Commit
git commit -m "Add Ubuntu Pro extension

- Exposes ubuntu_pro_status table with contract and service information
- Supports amd64 and arm64 architectures
- Includes automated installer script for Fleet deployment
- Follows established extension patterns from snap_packages"

# Push to your fork
git push origin main
```

### 3. Create GitHub Release (Optional)

If you want to make the binaries available via GitHub releases:

```bash
# Tag the release
git tag -a ubuntu_pro-v1.0.0 -m "Ubuntu Pro extension v1.0.0"
git push origin ubuntu_pro-v1.0.0
```

Then create a GitHub Release and upload the compiled binaries:
- `ubuntu_pro-amd64.ext`
- `ubuntu_pro-arm64.ext`

### 4. Deploy via Fleet

Once the binaries are in GitHub releases, you can use the installer script in Fleet:

**Fleet → Scripts → Add Script:**
- Name: "Install Ubuntu Pro Extension"
- Script: Upload `install-ubuntu-pro-extension.sh`
- Target: Ubuntu hosts

**Run the script** on your Ubuntu fleet and it will:
1. Auto-detect architecture
2. Download from GitHub releases
3. Install to `/var/fleetd/extensions/`
4. Configure osquery
5. Restart Orbit

### 5. Query in Fleet

```sql
-- Check Ubuntu Pro coverage
SELECT
  COUNT(*) AS total_hosts,
  SUM(CASE WHEN attached = 1 THEN 1 ELSE 0 END) AS pro_attached,
  ROUND(SUM(CASE WHEN attached = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) AS coverage_pct
FROM ubuntu_pro_status;

-- Alert on expiring contracts
SELECT
  h.hostname,
  p.contract_expires,
  p.days_until_expiration
FROM system_info h
JOIN ubuntu_pro_status p ON 1=1
WHERE p.days_until_expiration < 30
  AND p.days_until_expiration > 0;
```

---

## Differences from Your Original Implementation

### Simplified Approach

**Your version (comprehensive):**
- Full Ansible playbooks
- DEB package building
- Multiple deployment methods
- Extensive documentation

**This version (repo-native):**
- Single installer script
- Follows existing fleet-extensions patterns
- Leverages GitHub releases (already set up)
- Uses existing CI/CD (GitHub Actions)

### Same Core Functionality

Both implementations:
- ✅ Execute `pro status --format json`
- ✅ Parse JSON response
- ✅ Expose via osquery table
- ✅ Handle errors gracefully
- ✅ Support amd64 and arm64

---

## Why This Approach is Better

1. **Consistency:** Matches your boss's existing extension patterns exactly
2. **Maintenance:** Uses existing CI/CD and release infrastructure
3. **Simplicity:** One installer script vs. multiple deployment methods
4. **Integration:** Works with Fleet's existing script execution
5. **Discovery:** Other team members will find it in the extensions repo

---

## Testing Checklist

Before creating a PR or releasing:

- [ ] Code builds successfully (`make build`)
- [ ] Extension loads in osquery (`orbit shell --extension`)
- [ ] Table returns expected data (`SELECT * FROM ubuntu_pro_status`)
- [ ] Works on Ubuntu 20.04, 22.04, 24.04
- [ ] Works on amd64 architecture
- [ ] Works on arm64 architecture
- [ ] Installer script downloads and installs correctly
- [ ] Extension auto-loads after Orbit restart
- [ ] Handles "not attached" state gracefully
- [ ] Handles missing ubuntu-advantage-tools package

---

## Future Enhancements

Potential improvements:

1. **GitHub Actions:** Add workflow to auto-build and release binaries
2. **Additional Tables:** Add `ubuntu_pro_security_status` table
3. **Caching:** Cache JSON response for performance
4. **ESM Packages:** Track ESM package installations
5. **Compliance Policies:** Pre-built Fleet policies for compliance

---

## Support

- **Repository:** https://github.com/allenhouchins/fleet-extensions
- **Pattern Reference:** See `snap_packages/` for Linux extension pattern
- **Installer Reference:** See `snap_packages/install-snap-packages-extension.sh`

---

**Status:** ✅ Ready for testing and deployment
