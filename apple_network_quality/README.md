# Apple Network Quality Extension

An osquery extension that exposes macOS network quality metrics from the built-in `networkQuality` command as a native table.

## Overview

This extension creates an `apple_network_quality` table that provides network throughput, latency, and responsiveness metrics measured against Apple's CDN infrastructure. It wraps the macOS `networkQuality` tool (available in macOS 12+) and parses its JSON output into queryable columns.

## Table Schema

The `apple_network_quality` table has the following columns:

### Throughput Metrics

| Column Name | Type | Description |
|-------------|------|-------------|
| dl_throughput_bps | BIGINT | Download throughput in bits per second |
| ul_throughput_bps | BIGINT | Upload throughput in bits per second |
| dl_throughput_mbps | DOUBLE | Download throughput in Mbps |
| ul_throughput_mbps | DOUBLE | Upload throughput in Mbps |
| responsiveness | DOUBLE | Responsiveness in RPM (higher is better, >200 is good) |
| dl_flows | INTEGER | Number of parallel download flows used |
| ul_flows | INTEGER | Number of parallel upload flows used |
| dl_bytes | BIGINT | Total bytes downloaded during test |
| ul_bytes | BIGINT | Total bytes uploaded during test |

### Latency Metrics (under load)

| Column Name | Type | Description |
|-------------|------|-------------|
| avg_tcp_handshake_ms | DOUBLE | Average TCP handshake latency (ms) |
| avg_tls_handshake_ms | DOUBLE | Average TLS handshake latency (ms) |
| avg_h2_latency_ms | DOUBLE | Average HTTP/2 request/response latency to CDN (ms) |
| avg_self_h2_latency_ms | DOUBLE | Average self-induced latency during load (ms) |

### Network Condition

| Column Name | Type | Description |
|-------------|------|-------------|
| interface_name | TEXT | Network interface (e.g., `en0`) |
| interface_type | TEXT | Connection type: `wifi`, `wiredEthernet`, `cellular` |
| protocol | TEXT | Protocol used: `h2` (HTTP/2), `h3` (HTTP/3) |
| proxy_state | TEXT | Proxy status: `not_proxied`, `proxied` |
| ecn | TEXT | ECN status: `ecn_disabled`, `ecn_enabled` |
| l4s | TEXT | L4S (Low Latency) status: `disabled`, `enabled` |

### Test Metadata

| Column Name | Type | Description |
|-------------|------|-------------|
| test_endpoint | TEXT | Apple CDN server used (e.g., `defra1-edge-fx-046.aaplimg.com`) |
| start_date | TEXT | Test start timestamp |
| end_date | TEXT | Test end timestamp |
| os_version | TEXT | macOS version |

## Example Queries

### Basic network quality check
```sql
SELECT
    dl_throughput_mbps AS download_mbps,
    ul_throughput_mbps AS upload_mbps,
    responsiveness AS rpm,
    interface_type,
    protocol
FROM apple_network_quality;
```

### Check latency under load
```sql
SELECT
    avg_tcp_handshake_ms AS tcp_ms,
    avg_tls_handshake_ms AS tls_ms,
    avg_h2_latency_ms AS http2_ms,
    avg_self_h2_latency_ms AS self_latency_ms,
    test_endpoint
FROM apple_network_quality;
```

### Network diagnostics report
```sql
SELECT
    interface_name,
    interface_type,
    protocol,
    proxy_state,
    ROUND(dl_throughput_mbps, 1) || ' / ' || ROUND(ul_throughput_mbps, 1) || ' Mbps' AS throughput,
    CAST(responsiveness AS INTEGER) || ' RPM' AS responsiveness,
    ROUND(avg_tls_handshake_ms, 0) || ' ms' AS tls_latency
FROM apple_network_quality;
```

### Identify network issues
```sql
SELECT
    CASE
        WHEN responsiveness < 50 THEN 'Poor'
        WHEN responsiveness < 200 THEN 'Moderate'
        ELSE 'Good'
    END AS quality,
    dl_throughput_mbps,
    avg_tls_handshake_ms,
    interface_type,
    proxy_state
FROM apple_network_quality;
```

### Fleet: Correlate with host info
```sql
SELECT
    s.hostname,
    n.interface_type,
    n.dl_throughput_mbps,
    n.ul_throughput_mbps,
    n.responsiveness,
    n.test_endpoint
FROM apple_network_quality n, system_info s;
```

## Requirements

- macOS 12 (Monterey) or later
- The `networkQuality` command must be available at `/usr/bin/networkQuality`
- Network connectivity to Apple's CDN (`mensura.cdn-apple.com`)
- osquery extension support

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
osqueryi --extension ./apple_network_quality.ext
```

Then in osqueryi:
```sql
SELECT * FROM apple_network_quality;
```

### With Orbit shell (for testing)
```bash
sudo /opt/orbit/bin/orbit shell -- --extension ./apple_network_quality.ext --allow-unsafe
```

Then run the query:
```sql
SELECT * FROM apple_network_quality;
```

The `--allow-unsafe` flag permits loading unsigned extensions.

### With Fleet
1. Build the extension: `make build`
2. Deploy the `apple_network_quality.ext` file to your Fleet-managed macOS hosts
3. Configure Fleet to load the extension
4. Run queries against the `apple_network_quality` table

## How It Works

1. **Command execution**:
   - Runs `/usr/bin/networkQuality -c -M 3`
   - `-c`: Outputs results in JSON format
   - `-M 3`: Limits test duration to 3 seconds maximum

2. **Metrics collection**:
   - Throughput: Measures download/upload capacity to Apple CDN
   - Responsiveness: Measures RPM (roundtrips per minute) - higher values indicate lower latency
   - Latency arrays: TCP handshake, TLS handshake, and HTTP/2 request/response times

3. **JSON parsing**:
   - Parses the structured JSON output
   - Computes averages for latency arrays
   - Converts throughput to human-readable Mbps

4. **Platform checks**:
   - Returns empty results on non-macOS systems
   - Returns empty results if `networkQuality` command is not found

## Operational Considerations

### Network Impact
- Each query runs an active network test against Apple's CDN
- Test duration is limited to 3 seconds (`-M 3` flag)
- Consider scheduling queries sparingly (e.g., daily or weekly) in Fleet

### Privacy
- The test connects to Apple's CDN servers
- Network characteristics and CDN endpoint information are exposed
- Review data handling policies for your environment

### Performance
- Query execution takes approximately 3-5 seconds
- Not suitable for high-frequency polling
- Consider using a background collector daemon for frequent measurements

## Error Handling

- If `networkQuality` is not available, returns an empty result
- If the command fails, returns an error with the failure reason
- On non-macOS systems, returns an empty result gracefully

## Development

### Prerequisites
- Go 1.21 or later
- macOS 12+ for testing
- osquery installed

### Building
```bash
# Install dependencies
make deps

# Build the extension (universal binary for Intel + Apple Silicon)
make build

# Run tests
make test

# Clean build artifacts
make clean
```

### Build Artifacts
- `apple_network_quality.ext` - Universal macOS binary (Intel + ARM64)
- `apple_network_quality-x86_64.ext` - Intel-only binary
- `apple_network_quality-arm64.ext` - Apple Silicon-only binary

## Related Resources

- [Apple networkQuality man page](https://keith.github.io/xcode-man-pages/networkQuality.8.html)
- [Apple Enterprise Network Requirements](https://support.apple.com/en-us/101555)
- [Responsiveness under Working Conditions (RPM)](https://support.apple.com/en-us/111894)

## License

This extension is part of the Fleet Extensions project. See the main project LICENSE file for details.
