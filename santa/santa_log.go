package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	kLogEntryPreface = "santad: "
)

// extractValues extracts key-value pairs from a Santa log line
func extractValues(line string) map[string]string {
	values := make(map[string]string)

	// Extract timestamp
	timestampRegex := regexp.MustCompile(`\[([^\]]+)\]`)
	if matches := timestampRegex.FindStringSubmatch(line); len(matches) > 1 {
		values["timestamp"] = matches[1]
	}

	// Extract key=value pairs after the kLogEntryPreface
	keyPos := strings.Index(line, kLogEntryPreface)
	if keyPos == -1 {
		return values
	}

	keyPos += len(kLogEntryPreface)
	remaining := line[keyPos:]

	// Parse key=value pairs separated by |
	pairs := strings.Split(remaining, "|")
	for _, pair := range pairs {
		if equalPos := strings.Index(pair, "="); equalPos != -1 {
			key := strings.TrimSpace(pair[:equalPos])
			value := strings.TrimSpace(pair[equalPos+1:])
			if key != "" && value != "" {
				values[key] = value
			}
		}
	}

	return values
}

// scrapeStream processes a stream of log lines and extracts relevant entries
func scrapeStream(scanner *bufio.Scanner, decision SantaDecisionType) []LogEntry {
	var entries []LogEntry

	for scanner.Scan() {
		line := scanner.Text()

		// Filter by decision type
		if decision == DecisionAllowed {
			if !strings.Contains(line, "decision=ALLOW") {
				continue
			}
		} else if decision == DecisionDenied {
			if !strings.Contains(line, "decision=DENY") {
				continue
			}
		}

		values := extractValues(line)
		if values["timestamp"] != "" {
			entry := LogEntry{
				Timestamp:   values["timestamp"],
				Application: values["path"],
				Reason:      values["reason"],
				SHA256:      values["sha256"],
			}
			entries = append(entries, entry)
		}
	}

	return entries
}

// scrapeCurrentLog reads the current Santa log file
func scrapeCurrentLog(decision SantaDecisionType) ([]LogEntry, error) {
	paths := GetDefaultPaths()

	file, err := os.Open(paths.LogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Santa log file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	return scrapeStream(scanner, decision), nil
}

// scrapeCompressedSantaLog reads a compressed Santa log file
func scrapeCompressedSantaLog(filePath string, decision SantaDecisionType) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open compressed log file %s: %v", filePath, err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader for %s: %v", filePath, err)
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	return scrapeStream(scanner, decision), nil
}

// newArchiveFileExists checks if a new archive file exists
func newArchiveFileExists(archiveIndex int) bool {
	paths := GetDefaultPaths()
	archivePath := fmt.Sprintf("%s.%d.gz", paths.LogPath, archiveIndex)

	_, err := os.Stat(archivePath)
	return err == nil
}

// scrapeSantaLog reads all Santa log files (current and archived)
func scrapeSantaLog(decision SantaDecisionType) ([]LogEntry, error) {
	var allEntries []LogEntry

	// Read current log
	currentEntries, err := scrapeCurrentLog(decision)
	if err != nil {
		return nil, err
	}
	allEntries = append(allEntries, currentEntries...)

	// Read archived logs
	for i := 0; ; i++ {
		if !newArchiveFileExists(i) {
			break
		}

		paths := GetDefaultPaths()
		archivePath := fmt.Sprintf("%s.%d.gz", paths.LogPath, i)

		archiveEntries, err := scrapeCompressedSantaLog(archivePath, decision)
		if err != nil {
			// Log error but continue with other archives
			fmt.Printf("Warning: failed to read archive %s: %v\n", archivePath, err)
			continue
		}

		allEntries = append(allEntries, archiveEntries...)
	}

	return allEntries, nil
}
