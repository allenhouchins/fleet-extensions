# SentinelOne osquery Extension Design

## Overview
This document outlines the design for a SentinelOne osquery extension that provides endpoint security status and threat intelligence data through osquery tables, supporting macOS and Windows platforms.

### Design Principles

1. **Graceful Degradation:** Missing binary or permission errors return empty results, not errors
2. **Platform Parity:** Consistent table schema across platforms, with platform-specific fields clearly marked
3. **Robust Parsing:** Case-insensitive regex with flexible whitespace handling
4. **Critical Fields:** Version and protection status are required; other fields optional
5. **CrowdStrike Alignment:** Follow patterns established by crowdstrike_falcon extension
6. **Testability:** Comprehensive mocks and test cases for all scenarios

### Key Architectural Decisions

- **Path Detection:** Glob patterns for Windows version directories, priority search for macOS
- **Error Handling:** Partial parse allowed for optional fields, empty result for critical field failures
- **Privileges:** Require admin/root, detect permission denial gracefully
- **Agent ID:** Single column, populated on macOS, empty on Windows (future: registry lookup)
- **Boolean Format:** TEXT columns with "true"/"false" strings (matches existing patterns)

## Research Summary

### SentinelOne Agent Architecture

**CLI Tool Locations:**
- **Windows:** `C:\Program Files\SentinelOne\Sentinel Agent <Version>\SentinelCtl.exe`
- **Linux:** `/opt/sentinelone/bin/sentinelctl` or `/usr/local/bin/sentinelctl`
- **macOS:** `sentinelctl` (system path), agent at `/Library/Sentinel/sentinel-agent.bundle`

**Available Commands:**
1. `sentinelctl status` - Agent/monitor status, self-protection, infection state
2. `sentinelctl version` - Agent version, sentinelctl version, ranger version

**Platform-Specific Outputs:**

**Windows (SentinelCtl.exe status):**
```
Disable State: Not disabled by the user
SentinelMonitor is loaded
Self-Protection status: On
Monitor Build id: 22.2.3.6268+abc123-Release.x64
SentinelAgent is loaded
SentinelAgent is running as PPL
Mitigation policy: quarantineThreat
```

**Linux (sentinelctl control status):**
```
Agent state Enabled
Process Name | PID
-----------------------
orchestrator | 1234
network      | 1235
scanner      | 1236
agent        | 1237
firewall     | 1238
```

**macOS (sentinelctl status):**
```
Agent Version: 22.2.3.6268
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Install Date: 2024-01-15
Protection status: On
Infected status: Not Infected
ES Framework status: Running
FW Extension status: Running
Network Quarantine status: Not Quarantined
```

## Table Design

### Table Name: `sentinelone_info`

### Column Definitions

| Column Name | Type | Description | Platforms |
|------------|------|-------------|-----------|
| `agent_id` | TEXT | Unique agent UUID/identifier | All |
| `agent_version` | TEXT | SentinelOne agent version | All |
| `agent_loaded` | TEXT | Whether agent is loaded (true/false) | All |
| `monitor_loaded` | TEXT | Whether monitor is loaded (true/false) | Windows, Linux |
| `protection_status` | TEXT | Protection enabled status (On/Off) | All |
| `infected_status` | TEXT | Whether threats detected (Infected/Not Infected) | All |
| `self_protection_status` | TEXT | Tamper protection status (On/Off) | Windows, macOS |
| `network_quarantine_status` | TEXT | Network quarantine state | macOS |
| `install_date` | TEXT | Agent installation date | macOS |
| `es_framework_status` | TEXT | Endpoint Security framework status (macOS) | macOS |
| `fw_extension_status` | TEXT | Firewall extension status (macOS) | macOS |

### Data Struct (Go)

```go
type SentinelOneOutput struct {
    AgentID                 string
    AgentVersion            string
    AgentLoaded             bool
    MonitorLoaded           bool
    ProtectionStatus        string
    InfectedStatus          string
    SelfProtectionStatus    string
    NetworkQuarantineStatus string
    InstallDate             string
    ESFrameworkStatus       string // macOS only
    FWExtensionStatus       string // macOS only
}
```

## Implementation Strategy

### File Structure
```
tables/sentinelone/
├── sentinelone.go           # Main implementation
├── sentinelone_test.go      # Unit tests
└── BUILD.bazel              # Bazel build configuration
```

### Privilege Requirements

**CRITICAL:** SentinelOne CLI tools require elevated privileges:

- **Windows:** Must run with Administrator privileges
  - If run without admin: Command returns "Access is denied"
  - osquery typically runs as SYSTEM, so this should be satisfied
  - Testing: Verify behavior when osquery runs as non-admin user

- **macOS:** Requires Full Disk Access or specific TCC permissions
  - sentinelctl may require root or specific entitlements
  - Testing: Verify TCC requirements for reading agent status
  - Fallback: Return empty result with logged warning if permission denied

- **Linux:** Requires root or sudo privileges
  - sentinelctl typically requires root to read agent status
  - Testing: Verify behavior when run as non-root

**Implementation:** Check for permission errors explicitly and return graceful empty result rather than error state.

### Platform-Specific Implementations

#### Windows Implementation

**Path Detection Strategy:**
```go
// Priority search order for SentinelCtl.exe:
// 1. Use filepath.Glob to find version directories
// 2. If multiple versions found, use the highest version
// 3. Check both Program Files locations (x64 and x86)

sentinelCtlPaths := []string{
    `C:\Program Files\SentinelOne\Sentinel Agent *\SentinelCtl.exe`,
    `C:\Program Files (x86)\SentinelOne\Sentinel Agent *\SentinelCtl.exe`,
}

// Use filepath.Glob() to find matching paths
// Sort by version number (highest first)
// Return first match or empty string if none found
```

**Command Execution:**
```go
// Execute with timeout context
ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
defer cancel()

out, err := r.Runner.RunCmd(sentinelCtlPath, "status")
if err != nil {
    // Check for permission denied
    if strings.Contains(err.Error(), "Access is denied") {
        log.Printf("sentinelctl requires administrator privileges")
        return output, nil // Return empty, not error
    }
    return output, err
}
```

**Parsing Patterns (Case-Insensitive):**
```go
// Agent loaded status
agentLoadedRe := regexp.MustCompile(`(?i)SentinelAgent is (loaded|not loaded)`)
// Returns: []string{"SentinelAgent is loaded", "loaded"}

// Monitor loaded status
monitorLoadedRe := regexp.MustCompile(`(?i)SentinelMonitor is (loaded|not loaded)`)
// Returns: []string{"SentinelMonitor is loaded", "loaded"}

// Self-protection status
selfProtectionRe := regexp.MustCompile(`(?i)Self-Protection status:\s*(On|Off)`)
// Returns: []string{"Self-Protection status: On", "On"}

// Monitor Build ID (for version extraction)
buildIDRe := regexp.MustCompile(`(?i)Monitor Build id:\s*([0-9.]+)`)
// Returns: []string{"Monitor Build id: 22.2.3.6268+abc123-Release.x64", "22.2.3.6268"}
// Extract only the version number part, ignore build hash

// Mitigation policy (for future use)
mitigationPolicyRe := regexp.MustCompile(`(?i)Mitigation policy:\s*(.+)`)
// Returns: []string{"Mitigation policy: quarantineThreat", "quarantineThreat"}
```

**Agent ID Strategy:**
Windows doesn't expose agent ID in status output. Options:
1. Check Windows Registry: `HKLM\SOFTWARE\SentinelOne\` for agent UUID
2. Leave empty if not available from registry
3. Document as Windows limitation

#### macOS Implementation

**Path Detection Strategy:**
```go
// Priority search order for sentinelctl:
sentinelCtlPaths := []string{
    "/usr/local/bin/sentinelctl",
    "/opt/sentinelone/bin/sentinelctl",
}

// Use exec.LookPath("sentinelctl") as final fallback
// Check for /Library/Sentinel/sentinel-agent.bundle to verify installation
```

**Parsing Patterns (Case-Insensitive, Flexible Whitespace):**
```go
// Agent Version
versionRe := regexp.MustCompile(`(?i)Agent Version:\s*(.+)`)
// Returns: []string{"Agent Version: 22.2.3.6268", "22.2.3.6268"}

// Agent UUID/ID
idRe := regexp.MustCompile(`(?i)ID:\s*([a-f0-9-]+)`)
// Returns: []string{"ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}

// Install Date
installDateRe := regexp.MustCompile(`(?i)Install Date:\s*(.+)`)
// Returns: []string{"Install Date: 2024-01-15", "2024-01-15"}

// Protection Status
protectionRe := regexp.MustCompile(`(?i)Protection status:\s*(On|Off)`)
// Returns: []string{"Protection status: On", "On"}

// Infected Status
infectedRe := regexp.MustCompile(`(?i)Infected status:\s*(.+)`)
// Returns: []string{"Infected status: Not Infected", "Not Infected"}

// ES Framework Status
esFrameworkRe := regexp.MustCompile(`(?i)ES Framework status:\s*(.+)`)
// Returns: []string{"ES Framework status: Running", "Running"}

// Firewall Extension Status
fwExtensionRe := regexp.MustCompile(`(?i)FW Extension status:\s*(.+)`)
// Returns: []string{"FW Extension status: Running", "Running"}

// Network Quarantine Status
netQuarantineRe := regexp.MustCompile(`(?i)Network Quarantine status:\s*(.+)`)
// Returns: []string{"Network Quarantine status: Not Quarantined", "Not Quarantined"}
```

**Agent Loaded Detection:**
macOS doesn't show "agent loaded" in status output. Options:
1. Query osquery process table for sentinelone processes
2. Check if ES Framework status is "Running" as proxy
3. Assume loaded if status command succeeds

#### Linux Implementation (Future)
1. Check for `/opt/sentinelone/bin/sentinelctl`
2. Execute `sentinelctl control status`
3. Parse table output for process states
4. Query osquery process table for sentinelone processes

### Error Handling & Partial Parse Strategy

**Critical Fields (Must-Have):**
- `agent_version` - Required to identify agent
- `protection_status` - Core security indicator

**Optional Fields:**
- All other fields can be empty if parsing fails

**Behavior:**
1. **If critical fields fail to parse:** Return empty result (no row), log warning
2. **If optional fields fail to parse:** Populate with empty string, continue
3. **If command not found:** Return empty result (not an error)
4. **If permission denied:** Return empty result, log warning
5. **If command times out:** Return empty result after 10 seconds

**Example Partial Parse:**
```go
// If agent_id parse fails but version succeeds:
if output.AgentVersion == "" {
    // Critical field missing - return empty
    return []map[string]string{}, nil
}

// Build row with available data
row := map[string]string{
    "agent_id":                   output.AgentID,           // May be empty on Windows
    "agent_version":              output.AgentVersion,      // Must have value
    "agent_loaded":               utils.BoolToString(output.AgentLoaded),
    "monitor_loaded":             utils.BoolToString(output.MonitorLoaded),
    "protection_status":          output.ProtectionStatus,  // Must have value
    "infected_status":            output.InfectedStatus,    // Empty if parse failed
    "self_protection_status":     output.SelfProtectionStatus,
    "network_quarantine_status":  output.NetworkQuarantineStatus,
    "install_date":               output.InstallDate,
    "es_framework_status":        output.ESFrameworkStatus, // macOS only
    "fw_extension_status":        output.FWExtensionStatus, // macOS only
}
```

### Testing Strategy
- Mock command runner for unit tests
- Mock file system for installation detection
- Test cases:
  - Binary not present
  - Command execution error
  - Successful execution with full data
  - Parsing errors
  - Platform-specific field handling
  - Permission denied scenarios
  - Partial parse failures
  - Multiple version installations (Windows)
  - Agent in transitional states

### Mock Data Samples

#### Windows Mock Outputs

**Successful Status (Full Data):**
```go
var mockWindowsStatusFull = `Disable State: Not disabled by the user
SentinelMonitor is loaded
Self-Protection status: On
Monitor Build id: 22.2.3.6268+abc123-Release.x64
SentinelAgent is loaded
SentinelAgent is running as PPL
Mitigation policy: quarantineThreat`

// Expected parsed output:
// AgentVersion: "22.2.3.6268"
// AgentLoaded: true
// MonitorLoaded: true
// SelfProtectionStatus: "On"
```

**Agent Not Loaded:**
```go
var mockWindowsAgentNotLoaded = `Disable State: Not disabled by the user
SentinelMonitor is not loaded
Self-Protection status: Off
Monitor Build id: 22.2.3.6268+abc123-Release.x64
SentinelAgent is not loaded`

// Expected parsed output:
// AgentLoaded: false
// MonitorLoaded: false
// SelfProtectionStatus: "Off"
```

**Permission Denied:**
```go
var mockWindowsPermissionDenied = ``
// With error: "Access is denied"
// Expected: Return empty result, no error
```

**Agent Not Installed:**
```go
var mockWindowsNotInstalled = ``
// Binary not found at path
// Expected: Return empty result
```

#### macOS Mock Outputs

**Successful Status (Full Data):**
```go
var mockMacOSStatusFull = `Agent Version: 22.2.3.6268
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Install Date: 2024-01-15
Protection status: On
Infected status: Not Infected
ES Framework status: Running
FW Extension status: Running
Network Quarantine status: Not Quarantined`

// Expected parsed output:
// AgentID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
// AgentVersion: "22.2.3.6268"
// InstallDate: "2024-01-15"
// ProtectionStatus: "On"
// InfectedStatus: "Not Infected"
// ESFrameworkStatus: "Running"
// FWExtensionStatus: "Running"
// NetworkQuarantineStatus: "Not Quarantined"
```

**Infected System:**
```go
var mockMacOSInfected = `Agent Version: 22.2.3.6268
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Install Date: 2024-01-15
Protection status: On
Infected status: Infected
ES Framework status: Running
FW Extension status: Running
Network Quarantine status: Quarantined`

// Expected parsed output:
// InfectedStatus: "Infected"
// NetworkQuarantineStatus: "Quarantined"
```

**Partial Data (Missing Optional Fields):**
```go
var mockMacOSPartial = `Agent Version: 22.2.3.6268
ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
Protection status: On`

// Expected parsed output:
// AgentVersion: "22.2.3.6268" (critical field present)
// AgentID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
// ProtectionStatus: "On" (critical field present)
// Other fields: Empty strings
```

**Agent Not Installed:**
```go
var mockMacOSNotInstalled = ``
// Binary not found at path
// Expected: Return empty result
```

**Whitespace Variations:**
```go
var mockMacOSWhitespaceVariations = `Agent Version:  22.2.3.6268
ID:a1b2c3d4-e5f6-7890-abcd-ef1234567890
Protection status: On`

// Test that regex handles:
// - Double spaces after colon
// - No space after colon
// Expected: Same parsing as standard format
```

#### Test Case Matrix

| Test Case | Windows | macOS | Expected Behavior |
|-----------|---------|-------|-------------------|
| Binary not present | ✓ | ✓ | Empty result, no error |
| Permission denied | ✓ | ✓ | Empty result, logged warning |
| Full successful parse | ✓ | ✓ | All fields populated |
| Agent not loaded | ✓ | N/A | AgentLoaded: false |
| Infected system | N/A | ✓ | InfectedStatus: "Infected" |
| Partial data | ✓ | ✓ | Critical fields required, optional empty |
| Missing version | ✓ | ✓ | Empty result (critical field) |
| Whitespace variations | ✓ | ✓ | Parse successfully with trim |
| Case variations | ✓ | ✓ | Parse successfully (case-insensitive) |
| Command timeout | ✓ | ✓ | Empty result after 10s |
| Multiple versions (Win) | ✓ | N/A | Use highest version |

## Dependencies

### Go Packages
- `github.com/osquery/osquery-go` - osquery Go library
- `github.com/osquery/osquery-go/plugin/table` - Table plugin
- `github.com/pkg/errors` - Error handling
- `github.com/macadmins/osquery-extension/pkg/utils` - Utilities (Runner, FileSystem)
- Standard library: `context`, `fmt`, `os`, `regexp`, `runtime`, `strconv`, `strings`, `time`

### Bazel Dependencies
```python
deps = [
    "//pkg/utils",
    "@com_github_osquery_osquery_go//:osquery-go",
    "@com_github_osquery_osquery_go//plugin/table",
    "@com_github_pkg_errors//:errors",
]
```

## Comparison to CrowdStrike Falcon Extension

### Similarities
- Platform-specific implementations (runtime.GOOS switching)
- CLI tool execution and parsing
- Table-based data exposure
- Graceful degradation when agent not installed
- Process checking via osquery for verification

### Differences
- **CrowdStrike:** Uses plist output on macOS, simpler text parsing on Linux
- **SentinelOne:** Uses key-value text format on macOS, tabular format on Linux
- **CrowdStrike:** 5 columns focused on agent identity and RFM status
- **SentinelOne:** 11 columns including threat status, protection states, and platform-specific extensions
- **CrowdStrike:** Simpler output parsing (plist + regex)
- **SentinelOne:** More complex parsing with platform-specific fields

## Implementation Phases

### Phase 1: Core Implementation
1. Create package structure
2. Implement column definitions
3. Implement generate function with platform detection
4. Implement Windows support (priority)
5. Implement macOS support (priority)

### Phase 2: Testing
1. Write unit tests for Windows
2. Write unit tests for macOS
3. Add integration tests

### Phase 3: Linux Support (Future)
1. Research Linux-specific sentinelctl behavior
2. Implement Linux parsing
3. Add Linux tests

### Phase 4: Documentation
1. Create README with usage examples
2. Document table schema
3. Add example osquery queries

## Example osquery Queries

```sql
-- Get basic SentinelOne agent info
SELECT * FROM sentinelone_info;

-- Check if protection is enabled
SELECT agent_id, agent_version, protection_status
FROM sentinelone_info
WHERE protection_status = 'On';

-- Find infected systems
SELECT agent_id, infected_status, agent_version
FROM sentinelone_info
WHERE infected_status != 'Not Infected';

-- Verify agent is running
SELECT agent_id, agent_loaded, monitor_loaded
FROM sentinelone_info
WHERE agent_loaded = 'true' AND monitor_loaded = 'true';

-- macOS-specific: Check ES Framework
SELECT agent_id, es_framework_status, fw_extension_status
FROM sentinelone_info
WHERE es_framework_status != 'Running';
```

## References

### Research Sources
- [SentinelOne Agent Command Line Tool](https://www.sonicwall.com/support/knowledge-base/sentinelone-agent-command-line-tool/kA1VN0000000E7q0AE)
- [SentinelOne Installation - Windows](https://support.guardz.com/en/articles/10088017-sentinelone-installation-windows)
- [SentinelOne Installation - macOS](https://support.guardz.com/en/articles/10087946-sentinelone-installation-macos)
- [SentinelOne Agent Compliance Script](https://gist.github.com/keyboardcrunch/6c2451815eb48c42bc3efbc01a809a9d)
- [SentinelOne FAQ](https://www.sentinelone.com/faq/)

## Design Decisions

### Agent ID vs UUID (RESOLVED)
**Decision:** Use single `agent_id` column that contains:
- **macOS:** The UUID from `ID:` field in sentinelctl output
- **Windows:** Empty for now (requires registry lookup, marked as future enhancement)
- **Rationale:** Simplifies table schema, matches CrowdStrike pattern of single agent identifier

**Future Enhancement:** Add Windows Registry lookup for agent UUID:
```go
// HKLM\SOFTWARE\SentinelOne\AgentUUID or similar
// Research required to find correct registry key
```

### Version Detection on Windows (RESOLVED)
**Decision:** Use glob pattern to find version directory, extract version from Monitor Build ID
- **Path Strategy:** `filepath.Glob("C:\Program Files\SentinelOne\Sentinel Agent *\SentinelCtl.exe")`
- **Version Source:** Parse from "Monitor Build id: 22.2.3.6268+..." output
- **Multiple Versions:** Sort by version, use highest (or first if sorting fails)
- **Rationale:** Build ID is reliable source, path glob handles version number variation

### Linux Priority (RESOLVED)
**Decision:** Linux support deferred to Phase 3 (Future)
- **Rationale:** Windows and macOS are primary Fleet deployment targets
- **Platform Support:** Table will return empty result on Linux with log message
- **Implementation:** Add runtime.GOOS check that logs "Linux not yet supported"

### Boolean Field Representation (RESOLVED)
**Decision:** Use TEXT columns with "true"/"false" strings (via utils.BoolToString)
- **Rationale:** Matches CrowdStrike Falcon extension pattern
- **Consistency:** Aligns with existing osquery-extension codebase conventions
- **Query Pattern:** `WHERE agent_loaded = 'true'`

## Remaining Open Questions

1. **Additional Fields:** Are there other useful fields from `sentinelctl` we should include?
   - Mitigation policy (Windows)?
   - Threat count vs boolean infected status?
   - Last communication timestamp with management console?
   - Consider adding in future iterations based on user feedback

2. **Registry Access on Windows:** What is the correct registry path for agent UUID?
   - Requires testing on Windows system with SentinelOne installed
   - May require different approach if registry not accessible

3. **macOS TCC Requirements:** What specific permissions does sentinelctl need?
   - Full Disk Access?
   - Endpoint Security entitlement?
   - Requires testing on macOS with SentinelOne installed

## Implementation Readiness Checklist

### Design Phase (Complete)
- ✅ Research SentinelOne CLI tools and output formats
- ✅ Define table schema with 11 columns
- ✅ Document platform-specific parsing strategies
- ✅ Define concrete regex patterns for all platforms
- ✅ Establish error handling and partial parse behavior
- ✅ Create mock data samples for testing
- ✅ Resolve open questions (Agent ID, version detection, boolean format)
- ✅ Document privilege requirements
- ✅ Define path detection strategies

### Implementation Phase (Next)
1. **Create directory structure:** `tables/sentinelone/`
2. **Implement column definitions:** `SentinelOneColumns()` function
3. **Implement Windows support:**
   - Path glob for version detection
   - Status command execution
   - Regex parsing with mock tests
   - Permission error handling
4. **Implement macOS support:**
   - Priority path search
   - Status command execution
   - Key-value parsing with mock tests
   - Process verification
5. **Write comprehensive tests:**
   - Unit tests with all mock scenarios
   - Platform-specific test coverage
   - Error condition testing
6. **Create BUILD.bazel:** Dependencies and build configuration
7. **Integration testing:** Test on real systems with SentinelOne installed
8. **Documentation:** README with schema, queries, and examples

## Design Review Checklist

Before proceeding to implementation, verify:
- [x] All regex patterns are defined and concrete
- [x] Path detection strategy handles edge cases (multiple versions, x86/x64)
- [x] Error handling covers all failure modes
- [x] Mock data samples provided for all test scenarios
- [x] Privilege requirements documented
- [x] Critical vs optional fields defined
- [x] Platform-specific behavior documented
- [x] Alignment with CrowdStrike Falcon patterns verified

**Status:** Design is implementation-ready. All critical gaps identified by RedTeam analysis have been addressed.
