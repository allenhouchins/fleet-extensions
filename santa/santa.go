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
// Values from SNTCommonEnums.h in Santa source
type RuleState int

const (
	RuleStateAllowlist RuleState = iota
	RuleStateBlocklist
	RuleStateSilentBlock
	RuleStateRemove
	RuleStateAllowCompiler
	RuleStateAllowTransitive
	RuleStateAllowLocalBinary
	RuleStateAllowLocalSigningID
	RuleStateCEL
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
		return "Allow"
	case RuleStateBlocklist:
		return "Block"
	case RuleStateSilentBlock:
		return "SilentBlock"
	case RuleStateRemove:
		return "Remove"
	case RuleStateAllowCompiler:
		return "AllowCompiler"
	case RuleStateAllowTransitive:
		return "AllowTransitive"
	case RuleStateAllowLocalBinary:
		return "AllowLocalBinary"
	case RuleStateAllowLocalSigningID:
		return "AllowLocalSigningID"
	case RuleStateCEL:
		return "CEL"
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
	case "allow", "allowlist", "whitelist":
		return RuleStateAllowlist
	case "block", "blocklist", "blacklist":
		return RuleStateBlocklist
	case "silentblock", "silent_block":
		return RuleStateSilentBlock
	case "remove":
		return RuleStateRemove
	case "allowcompiler", "allow_compiler", "compiler":
		return RuleStateAllowCompiler
	case "allowtransitive", "allow_transitive", "transitive":
		return RuleStateAllowTransitive
	case "allowlocalbinary", "allow_local_binary":
		return RuleStateAllowLocalBinary
	case "allowlocalsigningid", "allow_local_signingid":
		return RuleStateAllowLocalSigningID
	case "cel":
		return RuleStateCEL
	default:
		return RuleStateUnknown
	}
}
