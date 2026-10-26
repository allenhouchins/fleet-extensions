# sshd_config Osquery Extension

An osquery extension that reports the OpenSSH server's **effective** configuration — the output of `sshd -G` — as a native osquery table.

## Overview

Reading `/etc/ssh/sshd_config` tells you what someone wrote down, not what sshd will do. The file leaves most settings at their compiled-in defaults, pulls in drop-ins through `Include` (`/etc/ssh/sshd_config.d/*.conf` on most Linux distributions and on macOS), and can override settings per connection with `Match` blocks. `sshd -G` resolves all of that and prints every setting with the value sshd will actually use. This table exposes that dump, one row per setting, so settings like `PermitRootLogin`, `PasswordAuthentication`, or the allowed ciphers can be checked across a fleet without anyone parsing config files.

The table reports configuration only. With OpenSSH 9.3 or later it returns rows on any host that has sshd installed, whether or not the server is running — on macOS, for instance, it reports the configuration Remote Login would use even while Remote Login is off. Older sshd has extra requirements; see [How sshd is invoked](#how-sshd-is-invoked). To find out whether sshd is actually listening, use `listening_ports`, `systemd_units`, or `launchd`.

## Table Schema

| Column Name | Type | Description |
|-------------|------|-------------|
| `keyword` | TEXT | Configuration keyword, lowercased (e.g. `permitrootlogin`) |
| `value` | TEXT | Effective value, exactly as sshd printed it (e.g. `prohibit-password`) |
| `connection_spec` | TEXT | The `-C` connection spec `Match` blocks were evaluated against; empty for the global configuration. See [Evaluating `Match` blocks](#evaluating-match-blocks) |

Notes on the rows:

- **Keywords are always lowercase.** sshd printed lowercase keywords until OpenSSH 10.4, which switched to mixed case (`PermitRootLogin`). The extension lowercases them so the same query works on every version. SQLite's `=` is case-sensitive, so write `keyword = 'permitrootlogin'`.
- **Repeatable keywords produce one row per value**, in the order sshd printed them: `hostkey`, `listenaddress`, `acceptenv`, `subsystem`, and so on.
- **Values are not split.** List settings such as `ciphers` and `kexalgorithms` come back as sshd's comma-separated string. Use `LIKE` or osquery's `split()` to look inside them.
- **Available keywords vary by version and platform.** Newer OpenSSH releases add keywords, and some builds add their own (Apple's sshd reports `applebasesystem`, for example). A keyword that does not exist in a host's sshd simply has no row.

## Evaluating `Match` blocks

Without a connection spec, sshd evaluates no `Match` blocks and prints the global configuration. To see what applies to a particular connection, constrain `connection_spec`. The value is passed to sshd as `-C` and uses sshd's own syntax: comma-separated `keyword=value` pairs drawn from `user`, `host`, `addr`, `laddr`, `lport`, and `rdomain`, plus the bare `invalid-user` flag on OpenSSH 9.9 and later.

```sql
SELECT keyword, value
FROM sshd_config
WHERE connection_spec = 'user=root,host=bastion.example.com,addr=10.0.0.5'
  AND keyword IN ('permitrootlogin', 'passwordauthentication');
```

- `=` and `IN (...)` are both supported. Each distinct spec runs sshd once, and its rows carry that spec in `connection_spec`.
- Other operators (`LIKE`, `!=`, ...) are not passed to sshd; they filter the global configuration's rows, which have an empty `connection_spec`.
- An invalid spec fails the query with sshd's error (`Invalid test mode specification ...`) rather than returning an empty result.
- A spec only changes the result when the host's configuration has a `Match` block that applies to it.
- **A partial spec needs OpenSSH 7.7 or later.** Older sshd requires `user`, `host`, and `addr` together, and fails the query on a spec such as `user=root` with `user, host and addr are all required when testing Match configs`. That affects RHEL/CentOS 7 and Amazon Linux 2 (7.4) and Ubuntu 18.04 (7.6).

To evaluate a spec per row of another table, use `CROSS JOIN` with the other table on the left. A plain `JOIN` lets SQLite scan `sshd_config` first, so the spec never reaches sshd and the join matches nothing. The example below passes only `user`, so it needs OpenSSH 7.7 or later.

```sql
-- Effective PasswordAuthentication for every local login account.
SELECT u.username, c.value AS passwordauthentication
FROM users u
CROSS JOIN sshd_config c ON c.connection_spec = 'user=' || u.username
WHERE u.uid >= 500 AND u.uid < 65534
  AND c.keyword = 'passwordauthentication';
```

## How sshd is invoked

| Query | sshd 9.3 and later | sshd before 9.3 |
|-------|--------------------|-----------------|
| No `connection_spec` constraint | `sshd -G` | `sshd -T` |
| `connection_spec = '<spec>'` | `sshd -G -T -C <spec>` | `sshd -T -C <spec>` |

`sshd -G` was added in OpenSSH 9.3 (March 2023). Several supported distributions still ship older OpenSSH — Ubuntu 20.04 (8.2), Ubuntu 22.04 (8.9), and Debian 12 (9.2) — so when sshd rejects `-G` as an unknown option, the extension retries with `-T`. RHEL 9 and Amazon Linux 2023 first shipped 8.7, but their current releases ship 9.9 and use `-G`. The two print the same dump. The difference is that `-T` also runs sshd's startup checks, which add two requirements:

- **Host keys must exist.** Debian and Ubuntu generate them when the package is installed; RHEL, Amazon Linux, and Alpine generate them the first time sshd starts. They persist after that.
- **On Debian and Ubuntu, sshd must be running.** `-T` requires the privilege separation directory `/run/sshd`, which `ssh.service` creates when it starts (`RuntimeDirectory=sshd`) and removes when it stops, and `/run` is cleared at every boot. On a host that has sshd installed but stopped or disabled, the query fails with `Missing privilege separation directory: /run/sshd`.

When either check fails, the query fails and reports sshd's error.

`-G -T -C` works around an OpenSSH quirk: despite the man page, every sshd from 9.3 on rejects `-C` unless `-T` is also given. With both flags, `-G` still prints the configuration and exits before `-T` loads any host keys, so on current sshd a connection spec never needs host keys or root.

The extension looks for sshd at `/usr/sbin/sshd` on macOS and at `/usr/sbin/sshd`, `/usr/bin/sshd`, `/sbin/sshd`, and `/usr/local/sbin/sshd` on Linux, then falls back to `PATH`. If no sshd is installed, the table returns no rows. If sshd rejects its configuration, the query fails with sshd's error message, so a broken `sshd_config` is reported instead of looking like a host with no settings.

## Example queries

Every effective setting:

```sql
SELECT keyword, value FROM sshd_config;
```

The settings most security baselines check:

```sql
SELECT keyword, value
FROM sshd_config
WHERE keyword IN (
  'permitrootlogin', 'passwordauthentication', 'kbdinteractiveauthentication',
  'permitemptypasswords', 'pubkeyauthentication', 'maxauthtries',
  'x11forwarding', 'allowtcpforwarding', 'loglevel', 'logingracetime'
);
```

Hosts still offering a CBC cipher, or a SHA-1 or MD5 MAC:

```sql
SELECT keyword, value
FROM sshd_config
WHERE (keyword = 'ciphers' AND value LIKE '%-cbc%')
   OR (keyword = 'macs' AND (value LIKE '%hmac-sha1%' OR value LIKE '%hmac-md5%'));
```

Every address sshd is configured to listen on:

```sql
SELECT value AS listen_address FROM sshd_config WHERE keyword = 'listenaddress';
```

### As a Fleet policy

A Fleet policy passes when its query returns a row. Writing the check as `NOT EXISTS` makes hosts without sshd pass instead of fail.

A query that errors does not fail the policy: Fleet stores no response for that host, which counts as neither passing nor failing. That happens when sshd rejects its configuration, when a connection spec is invalid or too partial for an old sshd, and when an older sshd can't run `-T` (see [How sshd is invoked](#how-sshd-is-invoked)). A broken `sshd_config` therefore shows up as a host with no policy result, not as a failing host.

```sql
-- Root cannot log in with a password.
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM sshd_config
  WHERE keyword = 'permitrootlogin'
    AND value NOT IN ('no', 'prohibit-password', 'forced-commands-only')
);
```

```sql
-- Password authentication is disabled.
SELECT 1 WHERE NOT EXISTS (
  SELECT 1 FROM sshd_config
  WHERE keyword = 'passwordauthentication' AND value != 'no'
);
```

## Building the Extension

1. Install dependencies:
   ```bash
   make deps
   ```
2. Build the extension:
   ```bash
   make build
   ```
   This produces:
   - macOS: `sshd_config.ext` (universal), `sshd_config-x86_64.ext` (Intel), `sshd_config-arm64.ext` (Apple Silicon)
   - Linux: `sshd_config-amd64.ext` (x86_64), `sshd_config-linux-arm64.ext` (ARM64)

   `make macos` and `make linux` build a single platform.
3. Run the tests:
   ```bash
   make test
   ```

## Requirements

- Go 1.26 or later to build
- OpenSSH server (`sshd`) on the host
- osquery or Fleet

## Usage

### With Fleet

```bash
sudo orbit shell -- --extension sshd_config.ext --allow-unsafe
```

### With standard osquery

```bash
osqueryi --extension=/path/to/sshd_config.ext
```

## Notes and limitations

- **Tested on macOS and Linux.** On macOS the extension was tested end to end in Fleet's osqueryd 5.24 against Apple's OpenSSH 10.3p1. On Linux, the table's code was run against each distribution's own sshd in container images of Ubuntu 20.04, 22.04, and 24.04, Debian 12 and 13, Rocky Linux 9, Amazon Linux 2 and 2023, Alpine 3.17 and 3.22, and Fedora. Those runs covered OpenSSH 7.4 through 10.2, both the `-G` path and the `-T` fallback, and arm64 plus amd64 (Ubuntu 22.04). Wherever sshd's requirements were met, the output matched `sshd -T` line for line, including `Match` evaluation. The Linux runs did not load the extension into osquery, and the containers had no systemd.
- **Windows is not supported.** Windows' optional OpenSSH Server ships `sshd.exe`, which accepts the same flags, but it has not been tested and no Windows binary is built.
- **No `-f`.** The table always reports the configuration at sshd's default path, which is the one the running server uses unless it was started with `-f`.
- **Not a liveness check.** See [Overview](#overview): the table reports configuration whether or not sshd is running.
- Passing `--verbose` to the extension (osquery does this automatically when it runs verbose) logs each sshd invocation to stderr.

## License

Same as the parent project.
