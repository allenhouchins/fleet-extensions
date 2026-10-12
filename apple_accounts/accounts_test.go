package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

// fixtureSchema is a trimmed copy of the Core Data schema accountsd uses for
// Accounts4.sqlite, with the account types a signed-in Mac typically has.
// Several of Apple's helper account types repeat the Apple Account's username.
const fixtureSchema = `
CREATE TABLE ZACCOUNTTYPE (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
  ZACCOUNTTYPEDESCRIPTION VARCHAR, ZIDENTIFIER VARCHAR);
CREATE TABLE ZACCOUNT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, Z_OPT INTEGER,
  ZACTIVE INTEGER, ZAUTHENTICATED INTEGER, ZACCOUNTTYPE INTEGER, ZPARENTACCOUNT INTEGER,
  ZACCOUNTDESCRIPTION VARCHAR, ZIDENTIFIER VARCHAR, ZUSERNAME VARCHAR);
INSERT INTO ZACCOUNTTYPE (Z_PK, ZACCOUNTTYPEDESCRIPTION, ZIDENTIFIER) VALUES
  (1, 'iCloud', 'com.apple.account.AppleAccount'),
  (2, 'Apple ID Authentication', 'com.apple.account.AppleIDAuthentication'),
  (3, 'iMessage', 'com.apple.account.IdentityServices'),
  (4, 'Google', 'com.apple.account.Google');`

func requireSQLite(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(sqlite3Path); err != nil {
		t.Skipf("%s not available: %v", sqlite3Path, err)
	}
}

func runSQLite(t *testing.T, path string, commands ...string) {
	t.Helper()
	args := append([]string{"-init", "/dev/null", "-batch", "-bail", path}, commands...)
	if out, err := exec.Command(sqlite3Path, args...).CombinedOutput(); err != nil {
		t.Fatalf("sqlite3 %s: %v\n%s", path, err, out)
	}
}

// writeAccountsDB creates an accounts database under home. committed is
// checkpointed into the database file. walOnly is left in the -wal file, as
// it is while accountsd has the database open.
func writeAccountsDB(t *testing.T, home, committed, walOnly string) string {
	t.Helper()
	dir := filepath.Join(home, "Library", "Accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "Accounts4.sqlite")
	runSQLite(t, path, "PRAGMA journal_mode=WAL;", fixtureSchema, committed)
	if walOnly != "" {
		runSQLite(t, path, ".dbconfig no_ckpt_on_close on", walOnly)
		if _, err := os.Stat(path + "-wal"); err != nil {
			t.Fatalf("fixture has no -wal file, so the test would not exercise it: %v", err)
		}
	}
	return path
}

// dirContents maps each file in dir to its contents.
func dirContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contents[e.Name()] = string(data)
	}
	return contents
}

func TestGenerateAppleAccounts(t *testing.T) {
	requireSQLite(t)
	root := t.TempDir()

	alice := filepath.Join(root, "alice")
	alicePath := writeAccountsDB(t, alice, `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 1, 'alice@icloud.com'),
  (2, 1, 1, 2, 'alice@icloud.com'),
  (3, 1, 1, 3, 'alice@icloud.com'),
  (4, 1, 1, 4, 'alice@gmail.com');`, "")

	// bob signed in while accountsd had the database open, so the account
	// exists only in the -wal file.
	bob := filepath.Join(root, "bob")
	bobPath := writeAccountsDB(t, bob, "", `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 0, 1, 'bob@example.com');`)
	bobBefore := dirContents(t, filepath.Dir(bobPath))

	// carol has never used anything backed by the Accounts framework.
	carol := filepath.Join(root, "carol")
	if err := os.MkdirAll(carol, 0o700); err != nil {
		t.Fatal(err)
	}

	listUsers = func(context.Context) []localUser {
		return []localUser{
			{UID: "501", Username: "alice", HomeDir: alice},
			{UID: "502", Username: "bob", HomeDir: bob},
			{UID: "503", Username: "carol", HomeDir: carol},
		}
	}
	t.Cleanup(func() { listUsers = localUsers })

	rows, err := generateAppleAccounts(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}

	want := []map[string]string{
		{"uid": "501", "username": "alice", "apple_account": "alice@icloud.com", "active": "1", "authenticated": "1", "path": alicePath},
		{"uid": "502", "username": "bob", "apple_account": "bob@example.com", "active": "1", "authenticated": "0", "path": bobPath},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows:\n got %v\nwant %v", rows, want)
	}

	if after := dirContents(t, filepath.Dir(bobPath)); !reflect.DeepEqual(after, bobBefore) {
		t.Errorf("querying changed the live database directory")
	}
}

func TestGenerateAppleAccountsColumnsMatchSchema(t *testing.T) {
	requireSQLite(t)
	home := t.TempDir()
	writeAccountsDB(t, home, `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 1, 'someone@icloud.com');`, "")

	listUsers = func(context.Context) []localUser {
		return []localUser{{UID: "501", Username: "someone", HomeDir: home}}
	}
	t.Cleanup(func() { listUsers = localUsers })

	rows, err := generateAppleAccounts(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	columns := appleAccountsColumns()
	if len(rows[0]) != len(columns) {
		t.Errorf("row has %d keys, schema has %d columns", len(rows[0]), len(columns))
	}
	for _, c := range columns {
		if _, ok := rows[0][c.Name]; !ok {
			t.Errorf("row is missing column %q", c.Name)
		}
	}
}

// A database osqueryd cannot read, most often because it lacks Full Disk
// Access, must fail the query rather than look like a user who is signed out.
func TestGenerateAppleAccountsUnreadableDatabase(t *testing.T) {
	requireSQLite(t)
	if os.Geteuid() == 0 {
		t.Skip("root can read the database regardless of its permissions")
	}
	root := t.TempDir()
	alice := filepath.Join(root, "alice")
	writeAccountsDB(t, alice, `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 1, 'alice@icloud.com');`, "")
	bob := filepath.Join(root, "bob")
	bobPath := writeAccountsDB(t, bob, `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 1, 'bob@icloud.com');`, "")
	if err := os.Chmod(bobPath, 0); err != nil {
		t.Fatal(err)
	}

	listUsers = func(context.Context) []localUser {
		return []localUser{
			{UID: "501", Username: "alice", HomeDir: alice},
			{UID: "502", Username: "bob", HomeDir: bob},
		}
	}
	t.Cleanup(func() { listUsers = localUsers })

	rows, err := generateAppleAccounts(context.Background(), table.QueryContext{})
	if err == nil || !strings.Contains(err.Error(), "Full Disk Access") {
		t.Errorf("got rows %v, err %v; want an error naming Full Disk Access", rows, err)
	}
}

func TestReadAppleAccountsNoDatabase(t *testing.T) {
	_, err := readAppleAccounts(context.Background(), t.TempDir())
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want fs.ErrNotExist", err)
	}
}

func TestReadAppleAccountsNoAppleAccount(t *testing.T) {
	requireSQLite(t)
	home := t.TempDir()
	writeAccountsDB(t, home, `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 4, 'someone@gmail.com');`, "")

	accounts, err := readAppleAccounts(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) != 0 {
		t.Errorf("got %v, want no accounts", accounts)
	}
}

func TestReadAppleAccountsRejectsLinkOutsideHome(t *testing.T) {
	requireSQLite(t)
	root := t.TempDir()
	victimPath := writeAccountsDB(t, filepath.Join(root, "victim"), `
INSERT INTO ZACCOUNT (Z_PK, ZACTIVE, ZAUTHENTICATED, ZACCOUNTTYPE, ZUSERNAME) VALUES
  (1, 1, 1, 1, 'victim@icloud.com');`, "")

	home := filepath.Join(root, "attacker")
	dir := filepath.Join(home, "Library", "Accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimPath, filepath.Join(dir, "Accounts4.sqlite")); err != nil {
		t.Fatal(err)
	}

	accounts, err := readAppleAccounts(context.Background(), home)
	if err == nil || !strings.Contains(err.Error(), "outside the home directory") {
		t.Errorf("got accounts %v, err %v; want an outside-the-home-directory error", accounts, err)
	}
}

func TestReadAppleAccountsUnexpectedSchema(t *testing.T) {
	requireSQLite(t)
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Accounts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	runSQLite(t, filepath.Join(dir, "Accounts4.sqlite"), "CREATE TABLE ZSOMETHINGELSE (Z_PK INTEGER);")

	_, err := readAppleAccounts(context.Background(), home)
	if err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Errorf("err = %v, want sqlite3's no such table error", err)
	}
}

func TestParseAccounts(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []appleAccount
	}{
		{
			name: "no matching rows",
			out:  "",
			want: nil,
		},
		{
			name: "quoted value and NULLs",
			out:  "apple_account,active,authenticated\r\n\"odd,name@icloud.com\",1,\r\nplain@icloud.com,0,1\r\n",
			want: []appleAccount{
				{AppleAccount: "odd,name@icloud.com", Active: "1", Authenticated: ""},
				{AppleAccount: "plain@icloud.com", Active: "0", Authenticated: "1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAccounts([]byte(tt.out))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDsclList(t *testing.T) {
	out := "_mbsetupuser            /var/setup\n" +
		"alice                   /Users/alice\n" +
		"bob                     /Volumes/Data/Home Directories/bob\n" +
		"nohome\n"
	want := map[string]string{
		"_mbsetupuser": "/var/setup",
		"alice":        "/Users/alice",
		"bob":          "/Volumes/Data/Home Directories/bob",
	}
	if got := parseDsclList([]byte(out)); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// localUsers runs dscl, so this checks the parsing against the host's real
// directory output: the account running the tests must be listed once, with
// its own UID and home directory.
func TestLocalUsersIncludesCurrentUser(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("dscl is macOS only")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	homeInfo, err := os.Stat(home)
	if err != nil {
		t.Skip(err)
	}
	if os.Getuid() == 0 {
		t.Skip("root's home is not a login account's")
	}

	var matches []localUser
	for _, u := range localUsers(context.Background()) {
		if info, err := os.Stat(u.HomeDir); err == nil && os.SameFile(info, homeInfo) {
			matches = append(matches, u)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("got %d users with home %s, want 1: %v", len(matches), home, matches)
	}
	if want := strconv.Itoa(os.Getuid()); matches[0].UID != want {
		t.Errorf("UID = %s, want %s", matches[0].UID, want)
	}
}

func TestIsLoginAccount(t *testing.T) {
	for name, want := range map[string]bool{
		"alice": true, "root": false, "daemon": false, "nobody": false, "_mbsetupuser": false,
	} {
		if got := isLoginAccount(name); got != want {
			t.Errorf("isLoginAccount(%q) = %v, want %v", name, got, want)
		}
	}
}
