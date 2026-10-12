package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// accountsDB is where accountsd keeps a user's Internet Accounts, relative to
// the home directory. Since macOS 27, ~/Library/Preferences/MobileMeAccounts.plist
// is an empty dictionary, so this Core Data store is the only place the
// signed-in Apple Account can still be read from.
const accountsDB = "Library/Accounts/Accounts4.sqlite"

// appleAccountQuery selects the Apple Account rows. Other account types live
// in the same table: Google, Exchange, and Apple's own helper accounts
// (com.apple.account.AppleIDAuthentication, IdentityServices, ...), which
// repeat the Apple Account's username and would produce duplicate rows.
const appleAccountQuery = `SELECT a.ZUSERNAME AS apple_account, a.ZACTIVE AS active, a.ZAUTHENTICATED AS authenticated
FROM ZACCOUNT a JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK
WHERE t.ZIDENTIFIER = 'com.apple.account.AppleAccount'
ORDER BY a.Z_PK;`

// sqlite3Path is swapped out in tests. Shelling out to the sqlite3 that ships
// with macOS keeps the extension free of cgo and of a bundled SQLite.
var sqlite3Path = "/usr/bin/sqlite3"

const (
	queryTimeout     = 10 * time.Second
	snapshotAttempts = 3
)

// appleAccount is one Apple Account row from a user's accounts database.
type appleAccount struct {
	AppleAccount  string
	Active        string
	Authenticated string
}

// readAppleAccounts returns the Apple Accounts recorded in the accounts
// database under home. The error wraps fs.ErrNotExist when the user has no
// database.
func readAppleAccounts(ctx context.Context, home string) ([]appleAccount, error) {
	path, err := resolveInHome(home, filepath.Join(home, accountsDB))
	if err != nil {
		return nil, err
	}

	snapshot, cleanup, err := snapshotDB(path)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return queryAppleAccounts(ctx, snapshot)
}

// resolveInHome resolves symlinks in path and checks the result is still
// inside home. osqueryd runs as root, so without this a user could link their
// database to another user's and be reported with that user's Apple Account.
func resolveInHome(home, path string) (string, error) {
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", err
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(realPath, realHome+string(filepath.Separator)) {
		return "", fmt.Errorf("%s resolves to %s, outside the home directory", path, realPath)
	}
	return realPath, nil
}

// snapshotDB copies the database and its write-ahead log into a new private
// directory and returns the copy's path.
//
// accountsd keeps the database open in WAL mode, so a recent change such as a
// sign-in can sit in the -wal file until the next checkpoint. Querying a copy
// sees that change without taking locks on the live database or creating
// files next to it. The database and log are copied separately, so the copy
// is retried if either changed while it was being made.
func snapshotDB(path string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "apple_accounts-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := filepath.Join(dir, filepath.Base(path))

	for attempt := 0; attempt < snapshotAttempts; attempt++ {
		before := fileStates(path, path+"-wal")
		if err := copyFile(path, dst); err != nil {
			cleanup()
			return "", nil, err
		}
		os.Remove(dst + "-wal")
		if err := copyFile(path+"-wal", dst+"-wal"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			cleanup()
			return "", nil, err
		}
		if fileStates(path, path+"-wal") == before {
			return dst, cleanup, nil
		}
	}
	cleanup()
	return "", nil, fmt.Errorf("%s kept changing while it was being copied", path)
}

// fileStates summarizes the size and modification time of each path, for
// detecting a write between two points in time. A missing file is recorded
// as such, so a -wal file appearing or disappearing also counts.
func fileStates(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			b.WriteString("-;")
			continue
		}
		fmt.Fprintf(&b, "%d/%d;", info.Size(), info.ModTime().UnixNano())
	}
	return b.String()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// queryAppleAccounts runs appleAccountQuery against the database at path.
func queryAppleAccounts(ctx context.Context, path string) ([]appleAccount, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	// -init /dev/null skips ~/.sqliterc, which could change the output mode.
	cmd := exec.CommandContext(ctx, sqlite3Path,
		"-init", "/dev/null", "-batch", "-bail", "-csv", "-header",
		path, appleAccountQuery)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("sqlite3: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("sqlite3: %w", err)
	}
	return parseAccounts(out)
}

// parseAccounts reads sqlite3's CSV output, which has a header row unless the
// query matched nothing, in which case it is empty.
func parseAccounts(out []byte) ([]appleAccount, error) {
	records, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing sqlite3 output: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}

	column := map[string]int{}
	for i, name := range records[0] {
		column[name] = i
	}
	field := func(record []string, name string) string {
		if i, ok := column[name]; ok && i < len(record) {
			return record[i]
		}
		return ""
	}

	accounts := make([]appleAccount, 0, len(records)-1)
	for _, record := range records[1:] {
		accounts = append(accounts, appleAccount{
			AppleAccount:  field(record, "apple_account"),
			Active:        field(record, "active"),
			Authenticated: field(record, "authenticated"),
		})
	}
	return accounts, nil
}
