package main

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// collectSantaRules reads Santa rules from the database
func collectSantaRules() ([]RuleEntry, error) {
	paths := GetDefaultPaths()

	// Check if Santa database exists
	if _, err := os.Stat(paths.DatabasePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Santa database not found at %s", paths.DatabasePath)
	}

	// Copy the database to a temporary location to avoid locking issues
	srcFile, err := os.Open(paths.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Santa database: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(paths.TempDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary database: %v", err)
	}
	defer dstFile.Close()
	defer os.Remove(paths.TempDBPath) // Clean up temp file

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy database: %v", err)
	}
	dstFile.Close()

	// Open the temporary database
	db, err := sql.Open("sqlite3", paths.TempDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open temporary database: %v", err)
	}
	defer db.Close()

	// Query the rules table with all available columns
	rows, err := db.Query(`
		SELECT 
			identifier,
			state,
			type,
			custommsg
		FROM rules
		ORDER BY identifier
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %v", err)
	}
	defer rows.Close()

	var rules []RuleEntry
	for rows.Next() {
		var identifier, customMsg sql.NullString
		var stateInt, typeInt sql.NullInt64

		err := rows.Scan(&identifier, &stateInt, &typeInt, &customMsg)
		if err != nil {
			fmt.Printf("Warning: failed to scan rule row: %v\n", err)
			continue
		}

		if !identifier.Valid {
			continue
		}

		rule := RuleEntry{
			Identifier: identifier.String,
		}

		// Parse rule type from integer
		if typeInt.Valid {
			rule.Type = getRuleTypeFromInt(int(typeInt.Int64))
		} else {
			rule.Type = RuleTypeUnknown
		}

		// Parse rule state from integer
		if stateInt.Valid {
			rule.State = getRuleStateFromInt(int(stateInt.Int64))
		} else {
			rule.State = RuleStateUnknown
		}

		// Parse custom message
		if customMsg.Valid {
			rule.CustomMessage = customMsg.String
		} else {
			rule.CustomMessage = ""
		}

		rules = append(rules, rule)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rules: %v", err)
	}

	return rules, nil
}

// getRuleTypeFromInt converts integer type value to RuleType
func getRuleTypeFromInt(typeInt int) RuleType {
	switch typeInt {
	case 1000:
		return RuleTypeBinary
	case 2000:
		return RuleTypeCertificate
	case 3000:
		return RuleTypeTeamID
	case 4000:
		return RuleTypeSigningID
	case 5000:
		return RuleTypeCDHash
	default:
		return RuleTypeUnknown
	}
}

// getRuleStateFromInt converts integer state value to RuleState
func getRuleStateFromInt(stateInt int) RuleState {
	switch stateInt {
	case 1:
		return RuleStateWhitelist
	case 2:
		return RuleStateBlacklist
	default:
		return RuleStateUnknown
	}
}

// getRuleTypeNameFromDB converts database type string to RuleType
func getRuleTypeNameFromDB(typeStr string) RuleType {
	switch strings.ToLower(typeStr) {
	case "binary":
		return RuleTypeBinary
	case "certificate":
		return RuleTypeCertificate
	case "teamid":
		return RuleTypeTeamID
	case "signingid":
		return RuleTypeSigningID
	case "cdhash":
		return RuleTypeCDHash
	default:
		return RuleTypeUnknown
	}
}

// getRuleStateNameFromDB converts database state string to RuleState
func getRuleStateNameFromDB(stateStr string) RuleState {
	switch strings.ToLower(stateStr) {
	case "whitelist":
		return RuleStateWhitelist
	case "blacklist":
		return RuleStateBlacklist
	default:
		return RuleStateUnknown
	}
}
