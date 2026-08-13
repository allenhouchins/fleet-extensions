package main

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// userHome is a local account whose home directory may hold agent history.
type userHome struct {
	Username string
	HomeDir  string
}

// discoverUsers lists the accounts whose home directories should be searched.
//
// Under Fleet, osqueryd runs as root, so os.UserHomeDir() points at the root
// account and would find nothing. Every user's home directory has to be
// enumerated instead. Username lookups are deliberately best-effort: these
// binaries are built without cgo, so os/user cannot resolve macOS
// OpenDirectory accounts and the home directory name is used instead.
func discoverUsers() []userHome {
	homes := map[string]string{} // home directory -> username

	add := func(username, home string) {
		if home == "" || username == "" {
			return
		}
		home = filepath.Clean(home)
		if info, err := os.Stat(home); err != nil || !info.IsDir() {
			return
		}
		if _, exists := homes[home]; !exists {
			homes[home] = username
		}
	}

	// The invoking user, which covers running the extension under osqueryi as
	// a normal account.
	if current, err := user.Current(); err == nil {
		add(current.Username, current.HomeDir)
	}

	switch runtime.GOOS {
	case "darwin":
		for _, name := range subdirs("/Users") {
			if strings.HasPrefix(name, ".") || name == "Shared" || name == "Guest" {
				continue
			}
			add(name, filepath.Join("/Users", name))
		}
	case "windows":
		usersDir := filepath.Join(os.Getenv("SystemDrive")+string(filepath.Separator), "Users")
		if os.Getenv("SystemDrive") == "" {
			usersDir = `C:\Users`
		}
		skip := map[string]bool{
			"Public": true, "Default": true, "Default User": true,
			"All Users": true, "defaultuser0": true,
		}
		for _, name := range subdirs(usersDir) {
			if skip[name] {
				continue
			}
			add(name, filepath.Join(usersDir, name))
		}
	default:
		for _, u := range parsePasswd("/etc/passwd") {
			add(u.Username, u.HomeDir)
		}
		for _, name := range subdirs("/home") {
			add(name, filepath.Join("/home", name))
		}
	}

	users := make([]userHome, 0, len(homes))
	for home, username := range homes {
		users = append(users, userHome{Username: username, HomeDir: home})
	}
	// Stable ordering keeps query results comparable between runs.
	sort.Slice(users, func(i, j int) bool { return users[i].HomeDir < users[j].HomeDir })
	return users
}

// parsePasswd reads the accounts out of an /etc/passwd-style file, skipping
// the system accounts that cannot own an interactive agent session.
func parsePasswd(path string) []userHome {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Home directories shared by system accounts, which never hold agent data.
	nonHomes := map[string]bool{
		"/": true, "/nonexistent": true, "/dev/null": true,
		"/var/empty": true, "/bin": true, "/sbin": true, "/usr/sbin": true,
	}

	var users []userHome
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		username, home := fields[0], filepath.Clean(fields[5])
		if username == "" || nonHomes[home] {
			continue
		}
		users = append(users, userHome{Username: username, HomeDir: home})
	}
	return users
}
