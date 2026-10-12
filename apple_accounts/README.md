# apple_accounts Osquery Extension

An osquery extension that reports the Apple Account (Apple ID / iCloud) each local user is signed in to on macOS, as a native osquery table.

## Overview

The usual way to find a Mac's signed-in Apple Account was to read `~/Library/Preferences/MobileMeAccounts.plist`. On macOS 27 that file still exists but is an empty dictionary, so those queries now return nothing.

macOS still records the account in each user's `~/Library/Accounts/Accounts4.sqlite`, the private Core Data store that `accountsd` keeps for Internet Accounts. This table reads that database for every local user and returns one row per Apple Account, so `SELECT * FROM apple_accounts;` works without each Fleet customer writing and maintaining their own auto table construction (ATC) definition against an undocumented Apple schema.

The table does not check the macOS version. It reads `Accounts4.sqlite` wherever the file exists.

## Table Schema

| Column Name | Type | Description |
|-------------|------|-------------|
| `uid` | BIGINT | UID of the local user. Join to `users` on this column |
| `username` | TEXT | Short name of the local user |
| `apple_account` | TEXT | Apple Account the user is signed in to, usually an email address |
| `active` | INTEGER | `1` if `accountsd` marks the account active, `0` if not |
| `authenticated` | INTEGER | `1` if `accountsd` considers the account's credentials valid, `0` if not, typically because the user needs to sign in again |
| `path` | TEXT | The `Accounts4.sqlite` the row was read from |

`apple_account`, `active`, `authenticated`, and `path` have the same names and values as the columns of the ATC definition Fleet customers have been using as a workaround (see [Replacing the ATC workaround](#replacing-the-atc-workaround)), so queries written against that ATC table keep working.

Notes on the rows:

- **A user who is not signed in has no row.** To list users who are not signed in, `LEFT JOIN` from `users` (see below).
- **Only the Apple Account itself is reported.** The same database holds Google, Exchange, and other Internet Accounts, and Apple's own helper accounts (`com.apple.account.AppleIDAuthentication`, `com.apple.account.IdentityServices`, ...), which repeat the Apple Account's username. Those are left out.
- **The App Store and Media account is not covered.** A user can sign in to the App Store with a different Apple Account than the one in System Settings. This table reports the System Settings (iCloud) account.

## Example queries

Every signed-in Apple Account:

```sql
SELECT username, apple_account, active, authenticated FROM apple_accounts;
```

Every local login account, with its Apple Account if it has one:

```sql
SELECT u.username, a.apple_account, a.authenticated
FROM users u
LEFT JOIN apple_accounts a USING (uid)
WHERE u.uid >= 500 AND u.directory LIKE '/Users/%';
```

Apple Accounts that need the user to sign in again:

```sql
SELECT username, apple_account FROM apple_accounts WHERE authenticated = 0;
```

### As a Fleet policy

A Fleet policy passes when its query returns a row.

```sql
-- No user is signed in to an Apple Account outside the company domain.
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM apple_accounts WHERE apple_account NOT LIKE '%@example.com'
);
```

```sql
-- At least one user is signed in to an Apple Account.
SELECT 1 FROM apple_accounts WHERE active = 1 LIMIT 1;
```

`NOT EXISTS` policies are only safe because the table fails the query, instead of returning no rows, when it cannot read a database. See [Full Disk Access](#full-disk-access).

## Full Disk Access

`~/Library/Accounts` is protected by macOS privacy controls (TCC). Running as root is not enough: the process reading it needs **Full Disk Access**. Under Fleet, the extension is launched by osqueryd, so it is covered by the Full Disk Access grant for osqueryd in Fleet's recommended privacy preferences (PPPC) configuration profile. If the existing ATC workaround returns rows on a host, this table will too.

When a user's database exists but cannot be read, the query fails with an error such as:

```
error generating table: reading /Users/alice/Library/Accounts/Accounts4.sqlite: open /Users/alice/Library/Accounts/Accounts4.sqlite: operation not permitted (osqueryd needs Full Disk Access)
```

This is deliberate. A table that skipped unreadable databases would make a host without Full Disk Access look like a host where nobody is signed in, and a `NOT EXISTS` policy would pass on it. A user who has no database at all (someone who has never used anything backed by Internet Accounts) is not an error; they just have no row. The query also fails, with `sqlite3`'s message, if a database does not have the expected tables, so a future macOS schema change shows up as an error rather than as an empty result.

## How the database is read

- **Users.** Local accounts come from the local directory node (`dscl . -list /Users`), which gives each account's UID and home directory, including homes outside `/Users`. Service accounts (`_`-prefixed), `root`, `daemon`, and `nobody` are skipped. Any other directory in `/Users` is also searched, with the directory owner's UID and the directory name as `username`, which covers network accounts without a local record.
- **A private copy.** `accountsd` keeps the database open in WAL mode, so a recent change such as a sign-in can sit in `Accounts4.sqlite-wal` until the next checkpoint. The extension copies the database and its `-wal` file into a private temporary directory and queries the copy. That picks up those recent changes, which a read with SQLite's `immutable=1` would miss, and never takes locks on the live database or creates `-shm` files next to it. The copy is removed after each query. If either file changes while it is being copied, the copy is retried.
- **`/usr/bin/sqlite3`.** The query runs through the `sqlite3` that ships with macOS (as Fleet's `tcc_access` table does), which keeps the extension free of cgo and of a bundled SQLite. It is run with `-init /dev/null` so a `~/.sqliterc` cannot change the output format.
- **Symlinks.** osqueryd runs as root, so a database that resolves to a path outside the user's own home directory is rejected. Otherwise a user could link their database to another user's and be reported with that user's Apple Account.

The query is the one from the ATC workaround:

```sql
SELECT a.ZUSERNAME AS apple_account, a.ZACTIVE AS active, a.ZAUTHENTICATED AS authenticated
FROM ZACCOUNT a JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK
WHERE t.ZIDENTIFIER = 'com.apple.account.AppleAccount';
```

## Replacing the ATC workaround

Hosts using this ATC definition can drop it once the extension is deployed:

```yaml
config:
  auto_table_construction:
    apple_accounts:
      path: /Users/%/Library/Accounts/Accounts4.sqlite
      query: "SELECT a.ZUSERNAME AS apple_account, a.ZACTIVE AS active, a.ZAUTHENTICATED AS authenticated FROM ZACCOUNT a JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK WHERE t.ZIDENTIFIER = 'com.apple.account.AppleAccount'"
      columns:
        - apple_account
        - active
        - authenticated
      platform: darwin
```

Remove the ATC definition before (or at the same time as) deploying the extension: both register a table named `apple_accounts`, and osquery does not allow two tables with the same name. Existing queries keep working, and gain `uid` and `username`. Compared with the ATC, the extension also finds homes outside `/Users`, sees changes still in the `-wal` file, and fails loudly instead of returning nothing when it cannot read a database.

## Building the Extension

1. Install dependencies:
   ```bash
   make deps
   ```
2. Build the extension:
   ```bash
   make build
   ```
   This produces `apple_accounts.ext` (universal), `apple_accounts-x86_64.ext` (Intel), and `apple_accounts-arm64.ext` (Apple Silicon).
3. Run the tests:
   ```bash
   make test
   ```
   The tests build fixture databases with `/usr/bin/sqlite3`, including one whose account exists only in the `-wal` file.

## Requirements

- Go 1.26 or later to build
- macOS, with `/usr/bin/sqlite3` (part of the base system)
- Full Disk Access for osqueryd (see above)
- osquery or Fleet

## Usage

### With Fleet

```bash
sudo orbit shell -- --extension apple_accounts.ext --allow-unsafe
```

Run this from a terminal app that has Full Disk Access, since an interactive shell is attributed to the terminal rather than to osqueryd.

### With standard osquery

```bash
sudo osqueryi --extension=/path/to/apple_accounts.ext --allow-unsafe
```

## Notes and limitations

- **Not yet verified against a real `Accounts4.sqlite`.** The extension was tested end to end in osqueryd 5.21 on macOS 27, where it registered and, without Full Disk Access, failed with the error above. Its query is the one the ATC workaround has been running successfully on macOS 27, and the unit tests run that query against fixture databases built from the same tables. It has not yet been run with Full Disk Access against a live database.
- **Private schema.** `Accounts4.sqlite` is not a documented Apple interface. If a future macOS release changes it, the query fails with `sqlite3`'s error (for example `no such table: ZACCOUNT`) rather than returning wrong rows.
- **One copy per user per query.** Every query copies each user's database, so the table is not meant to be queried every few seconds.
- Passing `--verbose` to the extension (osquery does this automatically when it runs verbose) logs each database read and its account count to stderr.

## License

Same as the parent project.
