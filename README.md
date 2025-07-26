# Fleet Extensions

A collection of Go-based osquery extensions for Fleet and osquery, providing additional tables and integrations for Linux, macOS, and Windows systems.

## Extensions Summary

| Extension              | Description                                              | Platform(s)         |
|-----------------------|----------------------------------------------------------|---------------------|
| [snap_packages](snap_packages/README.md)         | Snap package information as a native osquery table       | Linux               |
| [macos_compatibility](macos_compatibility/README.md)   | macOS hardware/software compatibility table              | macOS               |
| [santa](santa/README.md)                 | Santa binary authorization rules and decisions           | macOS               |
| [system_profiler](system_profiler/README.md)       | macOS system profiler information as a native table      | macOS               |
| [nuget_packages](nuget_packages/README.md)         | NuGet package search results as a native osquery table   | macOS, Windows      |

## Extension Details

### [snap_packages](snap_packages/README.md)
- **Description:** Provides snap package information as a native osquery table.
- **Platforms:** Linux
- **Binaries:** `snap_packages-amd64.ext`, `snap_packages-arm64.ext`
- **Installation:** Automated install script available for Ubuntu systems

### [macos_compatibility](macos_compatibility/README.md)
- **Description:** Shows the compatibility of Mac hardware with the latest macOS versions.
- **Platforms:** macOS (Intel and Apple Silicon)
- **Binaries:** `macos_compatibility-x86_64.ext`, `macos_compatibility-arm64.ext`, `macos_compatibility.ext`

### [santa](santa/README.md)
- **Description:** Exposes Santa binary authorization rules, decision logs, and status information as native osquery tables.
- **Platforms:** macOS (Intel and Apple Silicon)
- **Binaries:** `santa-x86_64.ext`, `santa-arm64.ext`, `santa.ext`
- **Tables:** `santa_rules`, `santa_allowed`, `santa_denied`, `santa_status`

### [system_profiler](system_profiler/README.md)
- **Description:** Provides macOS system profiler information as a native osquery table.
- **Platforms:** macOS (Intel and Apple Silicon)
- **Binaries:** `system_profiler-x86_64.ext`, `system_profiler-arm64.ext`, `system_profiler.ext`

### [nuget_packages](nuget_packages/README.md)
- **Description:** Provides NuGet package search results as a native osquery table. Runs `nuget search` and parses the output.
- **Platforms:** macOS (Intel and Apple Silicon), Windows (amd64, arm64)
- **Binaries:** `nuget_packages-x86_64.ext`, `nuget_packages-arm64.ext`, `nuget_packages.ext`, `nuget_packages-amd64.exe`, `nuget_packages-arm64.exe`

## Automated Builds

This repository uses GitHub Actions to automatically build and release extensions when changes are pushed to the `main` branch. Each extension has its own workflow that:

- **Triggers on changes** to the extension's directory in the `main` branch
- **Builds binaries** for all supported platforms
- **Creates a GitHub release** with the tag `latest`
- **Uploads the appropriate binaries** as release assets

Extensions can also be built manually using the instructions below.

## Building Extensions

Each extension is self-contained in its own directory. To build an extension:

1. Navigate to the extension directory (e.g., `cd snap_packages`)
2. Install dependencies:
   ```bash
   make deps
   ```
3. Build the extension:
   - For **macOS extensions** (`macos_compatibility`, `santa`, `system_profiler`, `nuget_packages`):
     ```bash
     make build
     ```
     This produces:
     - A universal binary: `<extension>.ext` (works on both Intel and Apple Silicon Macs)
     - Architecture-specific binaries: `<extension>-x86_64.ext` (Intel), `<extension>-arm64.ext` (Apple Silicon)
   - For **Linux extension** (`snap_packages`):
     ```bash
     make build
     ```
     This produces:
     - `snap_packages-amd64.ext` (for x86_64/amd64 Linux)
     - `snap_packages-arm64.ext` (for ARM64 Linux)
   - For **Windows extension** (`nuget_packages`):
     ```bash
     make windows
     ```
     This produces:
     - `nuget_packages-amd64.exe` (for 64-bit Intel/AMD Windows)
     - `nuget_packages-arm64.exe` (for 64-bit ARM Windows)

## Usage

Extensions can be used with [Fleet](https://fleetdm.com/) or standard [osquery](https://osquery.io/):

### With Fleet
```bash
sudo orbit shell -- --extension <extension_name>.ext --allow-unsafe
```

### With osquery
```bash
osqueryi --extension=/path/to/<extension_name>.ext
```

See each extension's README for table schemas, example queries, and more details.

## License

This project is licensed under the same terms as the parent project. See LICENSE for details.
