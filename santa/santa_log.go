package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	kLogEntryPreface = "santad: "
	defaultLogPath   = "/var/db/santa/santa.log"
)

var maxEntries = 10_000

var timestampRegex = regexp.MustCompile(`\[([^\]]+)\]`)

// extractValues extracts key-value pairs from a Santa log line
func extractValues(line string) map[string]string {
	values := make(map[string]string, 8)

	// Extract timestamp
	if m := timestampRegex.FindStringSubmatch(line); len(m) > 1 {
		values["timestamp"] = m[1]
	}

	// Extract key=value pairs after the kLogEntryPreface
	pos := strings.Index(line, kLogEntryPreface)
	if pos == -1 {
		return values
	}
	rest := line[pos+len(kLogEntryPreface):]

	// Parse key=value pairs separated by |
	for _, seg := range strings.Split(rest, "|") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		k, v, ok := strings.Cut(seg, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if k != "" && v != "" {
			values[k] = v
		}
	}

	return values
}

// scrapeStream processes a stream of log lines and extracts relevant entries
func scrapeStream(ctx context.Context, scanner *bufio.Scanner, decision SantaDecisionType, rb *ringBuffer) error {
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()

		// Filter by decision type early to keep it fast
		switch decision {
		case DecisionAllowed:
			if !strings.Contains(line, "decision=ALLOW") {
				continue
			}
		case DecisionDenied:
			if !strings.Contains(line, "decision=DENY") {
				continue
			}
		}

		values := extractValues(line)
		if values["timestamp"] == "" {
			continue
		}

		rb.Add(LogEntry{
			Timestamp:   values["timestamp"],
			Application: values["path"],
			Reason:      values["reason"],
			SHA256:      values["sha256"],
		})
	}

	return scanner.Err()
}

// scrapeCurrentLog reads the current Santa log file
func scrapeCurrentLog(ctx context.Context, path string, decision SantaDecisionType, rb *ringBuffer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open Santa log file: %v", err)
	}
	defer file.Close()

	scanner := makeBufferedScanner(file)
	return scrapeStream(ctx, scanner, decision, rb)
}

// scrapeCompressedSantaLog reads a compressed Santa log file
func scrapeCompressedSantaLog(ctx context.Context, path string, decision SantaDecisionType, rb *ringBuffer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open compressed log file %s: %v", path, err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader for %s: %v", path, err)
	}
	defer gzReader.Close()

	scanner := makeBufferedScanner(gzReader)
	return scrapeStream(ctx, scanner, decision, rb)
}

func makeBufferedScanner(r io.Reader) *bufio.Scanner {
	return bufio.NewScanner(r)
}

// scrapeSantaLog reads all Santa log files (current and archived) and returns
// the most recent entries up to maxEntries limit.
func scrapeSantaLog(ctx context.Context, decision SantaDecisionType) ([]LogEntry, error) {
	return scrapeSantaLogFromBase(ctx, decision, defaultLogPath)
}

func scrapeSantaLogFromBase(ctx context.Context, decision SantaDecisionType, path string) ([]LogEntry, error) {
	rb := newRingBuffer(maxEntries)

	// Find highest archive index (0 = newest archive, higher = older)
	maxIdx := -1
	for i := 0; ; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d.gz", path, i)); err != nil {
			break
		}
		maxIdx = i
	}

	// 1) Archives oldest → newest: maxIdx, maxIdx-1, ..., 0
	for i := maxIdx; i >= 0; i-- {
		archivePath := fmt.Sprintf("%s.%d.gz", path, i)
		if err := scrapeCompressedSantaLog(ctx, archivePath, decision, rb); err != nil {
			return nil, err
		}
	}

	// 2) Current log last (newest overall)
	if err := scrapeCurrentLog(ctx, path, decision, rb); err != nil {
		return nil, err
	}

	// Return the last N entries (oldest → newest among those last N).
	return rb.SliceChrono(), nil
}
