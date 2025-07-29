package main

import (
	"strings"
)

// SantaDecisionType represents the type of Santa decision
type SantaDecisionType int

const (
	DecisionAllowed SantaDecisionType = iota
	DecisionDenied
)

// LogEntry represents a Santa log entry
type LogEntry struct {
	Timestamp   string
	Application string
	Reason      string
	SHA256      string
}

// RuleType represents the type of Santa rule
type RuleType int

const (
	RuleTypeBinary RuleType = iota
	RuleTypeCertificate
	RuleTypeTeamID
	RuleTypeSigningID
	RuleTypeCDHash
	RuleTypeUnknown
)

// RuleState represents the state of a Santa rule
type RuleState int

const (
	RuleStateAllowlist RuleState = iota
	RuleStateBlocklist
	RuleStateUnknown
)

// RuleEntry represents a Santa rule entry
type RuleEntry struct {
	Type          RuleType
	State         RuleState
	Identifier    string // SHA256, Team ID, Signing ID, CDHash value
	CustomMessage string
}

// SantaPaths contains the paths to Santa files
type SantaPaths struct {
	LogPath      string
	DatabasePath string
	TempDBPath   string
}

// GetDefaultPaths returns the default Santa file paths
func GetDefaultPaths() SantaPaths {
	return SantaPaths{
		LogPath:      "/var/db/santa/santa.log",
		DatabasePath: "/var/db/santa/rules.db",
		TempDBPath:   "/tmp/rules.db",
	}
}

// GetRuleTypeName returns the string representation of a rule type
func GetRuleTypeName(ruleType RuleType) string {
	switch ruleType {
	case RuleTypeBinary:
		return "Binary"
	case RuleTypeCertificate:
		return "Certificate"
	case RuleTypeTeamID:
		return "TeamID"
	case RuleTypeSigningID:
		return "SigningID"
	case RuleTypeCDHash:
		return "CDHash"
	default:
		return "Unknown"
	}
}

// GetRuleStateName returns the string representation of a rule state
func GetRuleStateName(ruleState RuleState) string {
	switch ruleState {
	case RuleStateAllowlist:
		return "Allowlist"
	case RuleStateBlocklist:
		return "Blocklist"
	default:
		return "Unknown"
	}
}

// GetTypeFromRuleName converts a rule name to a RuleType
func GetTypeFromRuleName(name string) RuleType {
	name = strings.ToLower(name)
	switch name {
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

// GetStateFromRuleName converts a rule name to a RuleState
func GetStateFromRuleName(name string) RuleState {
	name = strings.ToLower(name)
	switch name {
	case "allowlist", "whitelist":
		return RuleStateAllowlist
	case "blocklist", "blacklist":
		return RuleStateBlocklist
	default:
		return RuleStateUnknown
	}
}
