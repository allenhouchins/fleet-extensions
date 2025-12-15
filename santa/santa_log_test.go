package main

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractValues_ValidLine(t *testing.T) {
	line := `[2024-01-15 10:30:45.123] santad: decision=ALLOW|reason=CERT|sha256=abc123|path=/usr/bin/test`

	values := extractValues(line)

	if values["timestamp"] != "2024-01-15 10:30:45.123" {
		t.Errorf("expected timestamp '2024-01-15 10:30:45.123', got '%s'", values["timestamp"])
	}
	if values["decision"] != "ALLOW" {
		t.Errorf("expected decision 'ALLOW', got '%s'", values["decision"])
	}
	if values["reason"] != "CERT" {
		t.Errorf("expected reason 'CERT', got '%s'", values["reason"])
	}
	if values["sha256"] != "abc123" {
		t.Errorf("expected sha256 'abc123', got '%s'", values["sha256"])
	}
	if values["path"] != "/usr/bin/test" {
		t.Errorf("expected path '/usr/bin/test', got '%s'", values["path"])
	}
}

func TestExtractValues_QuotedValues(t *testing.T) {
	line := `[2024-01-15 10:30:45.123] santad: path="/Applications/My App.app"|reason='CERT'`

	values := extractValues(line)

	// Quotes should be trimmed
	if values["path"] != "/Applications/My App.app" {
		t.Errorf("expected path without quotes, got '%s'", values["path"])
	}
	if values["reason"] != "CERT" {
		t.Errorf("expected reason without quotes, got '%s'", values["reason"])
	}
}

func TestExtractValues_NoSantadPrefix(t *testing.T) {
	line := `[2024-01-15 10:30:45.123] other: decision=ALLOW`

	values := extractValues(line)

	// Should still get timestamp
	if values["timestamp"] != "2024-01-15 10:30:45.123" {
		t.Errorf("expected timestamp, got '%s'", values["timestamp"])
	}
	// But no other values since no "santad: " prefix
	if values["decision"] != "" {
		t.Errorf("expected empty decision, got '%s'", values["decision"])
	}
}

func TestExtractValues_EmptyLine(t *testing.T) {
	values := extractValues("")

	if len(values) != 0 {
		t.Errorf("expected empty map, got %v", values)
	}
}

func TestExtractValues_KeysAreLowercased(t *testing.T) {
	line := `[2024-01-15 10:30:45.123] santad: Decision=ALLOW|SHA256=abc123|Path=/test`

	values := extractValues(line)

	// Keys should be lowercased
	if _, ok := values["decision"]; !ok {
		t.Error("expected lowercase 'decision' key")
	}
	if _, ok := values["sha256"]; !ok {
		t.Error("expected lowercase 'sha256' key")
	}
	if _, ok := values["path"]; !ok {
		t.Error("expected lowercase 'path' key")
	}
}

func TestScrapeStream_FilterAllowed(t *testing.T) {
	logContent := `[2024-01-15 10:30:45.123] santad: decision=ALLOW|reason=CERT|sha256=abc123|path=/usr/bin/allowed
[2024-01-15 10:30:46.123] santad: decision=DENY|reason=BINARY|sha256=def456|path=/usr/bin/denied
[2024-01-15 10:30:47.123] santad: decision=ALLOW|reason=SCOPE|sha256=ghi789|path=/usr/bin/allowed2`

	rb := newRingBuffer(100)
	scanner := bufio.NewScanner(strings.NewReader(logContent))

	err := scrapeStream(context.Background(), scanner, DecisionAllowed, rb)
	if err != nil {
		t.Fatalf("scrapeStream error: %v", err)
	}

	entries := rb.SliceChrono()
	if len(entries) != 2 {
		t.Errorf("expected 2 ALLOW entries, got %d", len(entries))
	}

	if entries[0].Application != "/usr/bin/allowed" {
		t.Errorf("expected first app '/usr/bin/allowed', got '%s'", entries[0].Application)
	}
	if entries[1].Application != "/usr/bin/allowed2" {
		t.Errorf("expected second app '/usr/bin/allowed2', got '%s'", entries[1].Application)
	}
}

func TestScrapeStream_FilterDenied(t *testing.T) {
	logContent := `[2024-01-15 10:30:45.123] santad: decision=ALLOW|reason=CERT|sha256=abc123|path=/usr/bin/allowed
[2024-01-15 10:30:46.123] santad: decision=DENY|reason=BINARY|sha256=def456|path=/usr/bin/denied
[2024-01-15 10:30:47.123] santad: decision=DENY|reason=CERT|sha256=xyz999|path=/usr/bin/denied2`

	rb := newRingBuffer(100)
	scanner := bufio.NewScanner(strings.NewReader(logContent))

	err := scrapeStream(context.Background(), scanner, DecisionDenied, rb)
	if err != nil {
		t.Fatalf("scrapeStream error: %v", err)
	}

	entries := rb.SliceChrono()
	if len(entries) != 2 {
		t.Errorf("expected 2 DENY entries, got %d", len(entries))
	}
}

func TestScrapeStream_ContextCancellation(t *testing.T) {
	// Create a large log content
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("[2024-01-15 10:30:45.123] santad: decision=ALLOW|path=/test\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rb := newRingBuffer(100)
	scanner := bufio.NewScanner(strings.NewReader(sb.String()))

	err := scrapeStream(ctx, scanner, DecisionAllowed, rb)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got %v", err)
	}
}

func TestScrapeSantaLogFromBase_WithTestFile(t *testing.T) {
	// Create a temporary log file
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "santa.log")

	logContent := `[2024-01-15 10:30:45.123] santad: decision=ALLOW|reason=CERT|sha256=abc123|path=/usr/bin/test1
[2024-01-15 10:30:46.123] santad: decision=DENY|reason=BINARY|sha256=def456|path=/usr/bin/test2
[2024-01-15 10:30:47.123] santad: decision=ALLOW|reason=SCOPE|sha256=ghi789|path=/usr/bin/test3`

	err := os.WriteFile(logPath, []byte(logContent), 0644)
	if err != nil {
		t.Fatalf("failed to create test log file: %v", err)
	}

	entries, err := scrapeSantaLogFromBase(context.Background(), DecisionAllowed, logPath)
	if err != nil {
		t.Fatalf("scrapeSantaLogFromBase error: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestRuleTypeMapping(t *testing.T) {
	tests := []struct {
		input    int
		expected RuleType
	}{
		{500, RuleTypeCDHash},
		{1000, RuleTypeBinary},
		{2000, RuleTypeSigningID},
		{3000, RuleTypeCertificate},
		{4000, RuleTypeTeamID},
		{9999, RuleTypeUnknown},
	}

	for _, tc := range tests {
		result := getRuleTypeFromInt(tc.input)
		if result != tc.expected {
			t.Errorf("getRuleTypeFromInt(%d) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestRuleStateMapping(t *testing.T) {
	tests := []struct {
		input    int
		expected RuleState
	}{
		{1, RuleStateAllowlist},
		{2, RuleStateBlocklist},
		{3, RuleStateSilentBlock},
		{4, RuleStateRemove},
		{5, RuleStateAllowCompiler},
		{6, RuleStateAllowTransitive},
		{7, RuleStateAllowLocalBinary},
		{8, RuleStateAllowLocalSigningID},
		{9, RuleStateCEL},
		{99, RuleStateUnknown},
	}

	for _, tc := range tests {
		result := getRuleStateFromInt(tc.input)
		if result != tc.expected {
			t.Errorf("getRuleStateFromInt(%d) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}
