package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"howett.net/plist"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

const (
	networkExtensionPlistPath = "/Library/Preferences/com.apple.networkextension.plist"
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"local_network_permissions",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin("local_network_permissions", columns(), generate))

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func columns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("bundle_id"),
		table.TextColumn("executable_path"),
		table.TextColumn("display_name"),
		table.TextColumn("type"),
		table.IntegerColumn("state"),
		table.TextColumn("provider_added"),
	}
}

func generate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	permissions, err := readLocalNetworkPermissions()
	if err != nil {
		// Return empty result on error (graceful degradation)
		return []map[string]string{}, nil
	}

	results := make([]map[string]string, 0, len(permissions))
	for _, perm := range permissions {
		results = append(results, map[string]string{
			"bundle_id":       perm.BundleID,
			"executable_path": perm.ExecutablePath,
			"display_name":    perm.DisplayName,
			"type":            perm.Type,
			"state":           strconv.Itoa(perm.State),
			"provider_added":  perm.ProviderAdded,
		})
	}

	return results, nil
}

// LocalNetworkPermission represents a single app's local network permission entry
type LocalNetworkPermission struct {
	BundleID       string
	ExecutablePath string
	DisplayName    string
	Type           string
	State          int
	ProviderAdded  string
}

// NSKeyedArchive represents the structure of an NSKeyedArchiver plist
type NSKeyedArchive struct {
	Archiver string        `plist:"$archiver"`
	Objects  []interface{} `plist:"$objects"`
	Top      plist.UID     `plist:"$top"`
	Version  int           `plist:"$version"`
}

func readLocalNetworkPermissions() ([]LocalNetworkPermission, error) {
	data, err := os.ReadFile(networkExtensionPlistPath)
	if err != nil {
		return nil, err
	}

	// First, unmarshal into a generic map to handle the NSKeyedArchiver structure
	var archive map[string]interface{}
	_, err = plist.Unmarshal(data, &archive)
	if err != nil {
		return nil, err
	}

	// Get the $objects array which contains all archived objects
	objects, ok := archive["$objects"].([]interface{})
	if !ok {
		return nil, nil
	}

	return extractPermissionsFromObjects(objects), nil
}

func extractPermissionsFromObjects(objects []interface{}) []LocalNetworkPermission {
	var permissions []LocalNetworkPermission

	// Iterate through all objects looking for application permission dictionaries
	for _, obj := range objects {
		dict, ok := obj.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this looks like an application permission entry
		// These have keys like: bundleid, displayname, path, state, type, providerAdded
		if !isAppPermissionDict(dict, objects) {
			continue
		}

		perm := extractPermissionFromDict(dict, objects)
		if perm.BundleID != "" || perm.ExecutablePath != "" {
			permissions = append(permissions, perm)
		}
	}

	return permissions
}

func isAppPermissionDict(dict map[string]interface{}, objects []interface{}) bool {
	// Check for NS.keys and NS.objects which indicate an NSDictionary
	nsKeys, hasKeys := dict["NS.keys"].([]interface{})
	_, hasObjects := dict["NS.objects"].([]interface{})

	if !hasKeys || !hasObjects {
		return false
	}

	// Check if the keys include characteristic app permission fields
	hasCharacteristicKeys := false
	for _, keyRef := range nsKeys {
		keyStr := resolveUID(keyRef, objects)
		if keyStr == "bundleid" || keyStr == "path" || keyStr == "displayname" {
			hasCharacteristicKeys = true
			break
		}
	}

	return hasCharacteristicKeys
}

func extractPermissionFromDict(dict map[string]interface{}, objects []interface{}) LocalNetworkPermission {
	perm := LocalNetworkPermission{}

	nsKeys, ok := dict["NS.keys"].([]interface{})
	if !ok {
		return perm
	}

	nsObjects, ok := dict["NS.objects"].([]interface{})
	if !ok {
		return perm
	}

	// Build a map of resolved keys to resolved values
	for i, keyRef := range nsKeys {
		if i >= len(nsObjects) {
			break
		}

		key := resolveUID(keyRef, objects)
		value := resolveUID(nsObjects[i], objects)

		switch key {
		case "bundleid":
			if s, ok := value.(string); ok {
				perm.BundleID = s
			}
		case "path":
			if s, ok := value.(string); ok {
				perm.ExecutablePath = strings.TrimPrefix(s, "file://")
			}
		case "displayname":
			if s, ok := value.(string); ok {
				perm.DisplayName = s
			}
		case "type":
			if s, ok := value.(string); ok {
				perm.Type = s
			}
		case "state":
			perm.State = toInt(value)
		case "providerAdded":
			if s, ok := value.(string); ok {
				perm.ProviderAdded = s
			}
		}
	}

	return perm
}

// resolveUID resolves a plist.UID reference to its actual value in the objects array
func resolveUID(ref interface{}, objects []interface{}) interface{} {
	switch v := ref.(type) {
	case plist.UID:
		idx := int(v)
		if idx >= 0 && idx < len(objects) {
			// Don't recursively resolve - just return the direct value
			return objects[idx]
		}
	case uint64:
		idx := int(v)
		if idx >= 0 && idx < len(objects) {
			return objects[idx]
		}
	}
	return ref
}

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case uint64:
		return int(val)
	case float64:
		return int(val)
	}
	return 0
}
