package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// santaRulesExport represents the JSON structure from santactl rule --export
type santaRulesExport struct {
	Rules []santaRuleJSON `json:"rules"`
}

type santaRuleJSON struct {
	Policy     string `json:"policy"`
	RuleType   string `json:"rule_type"`
	Identifier string `json:"identifier"`
	CustomMsg  string `json:"custom_msg"`
	CustomURL  string `json:"custom_url"`
	Comment    string `json:"comment"`
	CELExpr    string `json:"cel_expr"`
}

// collectSantaRules reads Santa rules using santactl rule --export
func collectSantaRules() ([]RuleEntry, error) {
	// Create a temporary file for the export
	tmpFile, err := os.CreateTemp("", "santa_rules_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Run santactl rule --export
	cmd := exec.Command("santactl", "rule", "--export", tmpPath)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to export rules: %v", err)
	}

	// Read and parse the JSON file
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read exported rules: %v", err)
	}

	var export santaRulesExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, fmt.Errorf("failed to parse rules JSON: %v", err)
	}

	// Convert to RuleEntry slice
	rules := make([]RuleEntry, 0, len(export.Rules))
	for _, r := range export.Rules {
		rules = append(rules, RuleEntry{
			Identifier:    r.Identifier,
			Type:          getRuleTypeFromExport(r.RuleType),
			State:         getRuleStateFromExport(r.Policy),
			CustomMessage: r.CustomMsg,
		})
	}

	return rules, nil
}

// getRuleTypeFromExport converts export rule_type string to RuleType
func getRuleTypeFromExport(ruleType string) RuleType {
	switch strings.ToUpper(ruleType) {
	case "BINARY":
		return RuleTypeBinary
	case "CERTIFICATE":
		return RuleTypeCertificate
	case "TEAMID":
		return RuleTypeTeamID
	case "SIGNINGID":
		return RuleTypeSigningID
	case "CDHASH":
		return RuleTypeCDHash
	default:
		return RuleTypeUnknown
	}
}

// getRuleStateFromExport converts export policy string to RuleState
func getRuleStateFromExport(policy string) RuleState {
	switch strings.ToUpper(policy) {
	case "ALLOWLIST", "ALLOWLIST_COMPILER":
		return RuleStateAllowlist
	case "BLOCKLIST":
		return RuleStateBlocklist
	case "SILENT_BLOCKLIST":
		return RuleStateSilentBlock
	default:
		return RuleStateUnknown
	}
}

// getRuleTypeFromInt converts integer type value to RuleType
// Values from SNTCommonEnums.h in Santa source
func getRuleTypeFromInt(typeInt int) RuleType {
	switch typeInt {
	case 500:
		return RuleTypeCDHash
	case 1000:
		return RuleTypeBinary
	case 2000:
		return RuleTypeSigningID
	case 3000:
		return RuleTypeCertificate
	case 4000:
		return RuleTypeTeamID
	default:
		return RuleTypeUnknown
	}
}

// getRuleStateFromInt converts integer state value to RuleState
// Values from SNTCommonEnums.h in Santa source
func getRuleStateFromInt(stateInt int) RuleState {
	switch stateInt {
	case 1:
		return RuleStateAllowlist
	case 2:
		return RuleStateBlocklist
	case 3:
		return RuleStateSilentBlock
	case 4:
		return RuleStateRemove
	case 5:
		return RuleStateAllowCompiler
	case 6:
		return RuleStateAllowTransitive
	case 7:
		return RuleStateAllowLocalBinary
	case 8:
		return RuleStateAllowLocalSigningID
	case 9:
		return RuleStateCEL
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
	case "allowlist", "whitelist":
		return RuleStateAllowlist
	case "blocklist", "blacklist":
		return RuleStateBlocklist
	default:
		return RuleStateUnknown
	}
}
