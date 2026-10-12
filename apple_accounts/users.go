package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// localUser is an account whose home directory may hold an accounts database.
type localUser struct {
	UID      string
	Username string
	HomeDir  string
}

// localUsers lists the accounts whose home directories should be searched.
//
// Under Fleet, osqueryd runs as root, so every user's home directory has to be
// enumerated. The local directory node is authoritative for UIDs and for home
// directories outside /Users. Home directories in /Users that it does not
// know about, such as those of network accounts without a mobile account, are
// added with the directory owner's UID and the directory name as username.
func localUsers(ctx context.Context) []localUser {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	uids := parseDsclList(dscl(ctx, "UniqueID"))
	homes := parseDsclList(dscl(ctx, "NFSHomeDirectory"))

	var candidates []localUser
	for name, home := range homes {
		if uid, ok := uids[name]; ok && isLoginAccount(name) && filepath.IsAbs(home) {
			candidates = append(candidates, localUser{UID: uid, Username: name, HomeDir: filepath.Clean(home)})
		}
	}
	// Directory records go first, by name, so they win over the /Users scan
	// and the choice between two records sharing a home is stable.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Username < candidates[j].Username })

	entries, _ := os.ReadDir("/Users")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() && !strings.HasPrefix(name, ".") && name != "Shared" {
			candidates = append(candidates, localUser{Username: name, HomeDir: filepath.Join("/Users", name)})
		}
	}

	// Home directories are compared by device and inode rather than by path:
	// APFS is usually case-insensitive, and a home can be reached through a
	// symlink, so two different paths may be the same directory.
	seen := map[[2]uint64]bool{}
	var users []localUser
	for _, u := range candidates {
		info, err := os.Stat(u.HomeDir)
		if err != nil || !info.IsDir() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		id := [2]uint64{uint64(stat.Dev), stat.Ino}
		if seen[id] {
			continue
		}
		seen[id] = true
		if u.UID == "" {
			u.UID = strconv.FormatUint(uint64(stat.Uid), 10)
		}
		users = append(users, u)
	}
	// Stable ordering keeps query results comparable between runs.
	sort.Slice(users, func(i, j int) bool { return users[i].HomeDir < users[j].HomeDir })
	return users
}

// dscl lists one attribute of every record in the local directory node. A
// failure yields no output, which leaves the /Users scan to find accounts.
func dscl(ctx context.Context, attribute string) []byte {
	out, err := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-list", "/Users", attribute).Output()
	if err != nil {
		return nil
	}
	return out
}

// parseDsclList parses `dscl . -list /Users <attribute>` output, one record
// per line: the record name, padding, then the value. Values such as home
// directories may contain spaces; record names cannot.
func parseDsclList(out []byte) map[string]string {
	values := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		name, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		if !ok {
			continue
		}
		if value = strings.TrimSpace(value); value != "" {
			values[name] = value
		}
	}
	return values
}

// isLoginAccount reports whether a local directory record can belong to a
// person. Service accounts are prefixed with an underscore, and root, daemon,
// and nobody share or lack real home directories.
func isLoginAccount(name string) bool {
	switch name {
	case "root", "daemon", "nobody":
		return false
	}
	return !strings.HasPrefix(name, "_")
}
