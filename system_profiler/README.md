# System Profiler Osquery Extension (Go)

A Go-based osquery extension that provides macOS system profiler information as a native table. Query hardware and software details using SQL.

## Table Schema

| Column      | Type   | Description                                 |
|-------------|--------|---------------------------------------------|
| section     | TEXT   | Main section (e.g., "Hardware", "Software") |
| subsection  | TEXT   | Subsection within the main section           |
| key         | TEXT   | Property name                                |
| value       | TEXT   | Property value                               |
| data_type   | TEXT   | System Profiler data type (e.g., "SPHardwareDataType") |

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
   - Universal binary: `system_profiler.ext` (works on both Intel and Apple Silicon Macs)
   - Architecture-specific binaries: `system_profiler-x86_64.ext` (Intel), `system_profiler-arm64.ext` (Apple Silicon)

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension system_profiler.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/system_profiler.ext
```

### Example Queries

```sql
-- Get all system profiler information
SELECT * FROM system_profiler;

-- Get hardware information
SELECT * FROM system_profiler WHERE section = 'Hardware';

-- Get software information
SELECT * FROM system_profiler WHERE section = 'Software';

-- Find model information
SELECT * FROM system_profiler WHERE key LIKE '%Model%';

-- Get memory information
SELECT * FROM system_profiler WHERE section = 'Memory';
```

## Structure

```
├── main.go              # Main extension code
├── go.mod               # Go module definition
├── Makefile             # Build configuration
└── README.md            # This file
```

## Requirements

- Go 1.21 or later
- macOS system
- osquery or Fleet

## License

Same as the parent project.
