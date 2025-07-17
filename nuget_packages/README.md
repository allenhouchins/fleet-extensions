# NuGet Packages Osquery Extension (Go)

A Go-based osquery extension that provides NuGet package search results as a native table. It runs `nuget search` and parses the output into a table with package name, version, and description.

## Table Schema

| Column       | Type   | Description                        |
|--------------|--------|------------------------------------|
| name         | TEXT   | NuGet package name                 |
| version      | TEXT   | Package version                    |
| description  | TEXT   | Package description                |

## Building the Extension

1. Clone the repository
2. Install dependencies:
   ```bash
   make deps
   ```
3. Build the extension for your platform:
   - **macOS (universal and arch-specific):**
     ```bash
     make macos
     ```
     This produces:
     - Universal binary: `nuget_packages.ext` (works on both Intel and Apple Silicon Macs)
     - Architecture-specific binaries: `nuget_packages-x86_64.ext` (Intel), `nuget_packages-arm64.ext` (Apple Silicon)
   - **Windows (64-bit only):**
     ```bash
     make windows
     ```
     This produces:
     - `nuget_packages-amd64.exe` (for 64-bit Intel/AMD Windows)
     - `nuget_packages-arm64.exe` (for 64-bit ARM Windows)

## Usage

### With Fleet
```bash
sudo orbit shell -- --extension nuget_packages.ext --allow-unsafe
```

### With standard osquery
```bash
osqueryi --extension=/path/to/nuget_packages.ext
```

### On Windows
Use the `.exe` binary for your architecture:
```powershell
osqueryi.exe --extension=nuget_packages-amd64.exe
# or for ARM64
osqueryi.exe --extension=nuget_packages-arm64.exe
```

### Example Queries

```sql
-- List NuGet packages matching the default search ("json")
SELECT * FROM nuget_packages;
```

## Structure

```
├── main.go                  # Main extension code
├── go.mod                   # Go module definition
├── Makefile                 # Build configuration
└── README.md                # This file
```

## Requirements

- Go 1.21 or later
- macOS or Windows system (64-bit only)
- osquery or Fleet
- `nuget` CLI installed and available in PATH (or `nuget.exe` on Windows)

## License

Same as the parent project. 