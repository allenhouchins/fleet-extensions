# Software Update Osquery Extension

An osquery extension that lists available Apple software updates on macOS by running `softwareupdate --list --verbose` and exposing each item as a table row.

## Table Schema

| Column Name   | Type | Description |
|---------------|------|-------------|
| `label`       | TEXT | Update identifier from Software Update (e.g. `Command Line Tools for Xcode 26.4-26.4.1`) |
| `title`       | TEXT | Human-readable title |
| `version`     | TEXT | Version string reported by Software Update |
| `size`        | TEXT | Download size (e.g. `920104KiB`) |
| `recommended` | TEXT | `YES` or `NO` when present |
| `action`      | TEXT | Follow-up action when present (e.g. `restart`) |

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
   - Universal binary: `softwareupdate.ext` (Intel and Apple Silicon)
   - `softwareupdate-x86_64.ext`, `softwareupdate-arm64.ext`

## Requirements

- Go 1.21 or later
- macOS with `/usr/sbin/softwareupdate`
- osquery or Fleet

## Usage

### With Fleet

```bash
sudo orbit shell -- --extension softwareupdate.ext --allow-unsafe
```

### With standard osquery

```bash
osqueryi --extension=/path/to/softwareupdate.ext
```

## Example queries

List all pending updates:

```sql
SELECT * FROM softwareupdate;
```

Only updates that require a restart:

```sql
SELECT label, title, version FROM softwareupdate WHERE action = 'restart';
```

## Notes and limitations

- The extension only registers on macOS; on other platforms the table is not available.
- Listing updates can take noticeable time while Software Update scans; queries may be slower than typical osquery tables.
- Parsing follows the verbose list format from Apple’s tool; if the output format changes in a future macOS release, the parser may need an update.

## License

Same as the parent project.
