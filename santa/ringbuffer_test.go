package main

import (
	"testing"
)

func TestRingBuffer_Add_UnderCapacity(t *testing.T) {
	rb := newRingBuffer(5)

	rb.Add(LogEntry{Timestamp: "1", Application: "app1"})
	rb.Add(LogEntry{Timestamp: "2", Application: "app2"})
	rb.Add(LogEntry{Timestamp: "3", Application: "app3"})

	if rb.Len() != 3 {
		t.Errorf("expected len 3, got %d", rb.Len())
	}

	entries := rb.SliceChrono()
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}

	// Should be in chronological order
	if entries[0].Timestamp != "1" || entries[1].Timestamp != "2" || entries[2].Timestamp != "3" {
		t.Errorf("entries not in chronological order: %v", entries)
	}
}

func TestRingBuffer_Add_AtCapacity(t *testing.T) {
	rb := newRingBuffer(3)

	rb.Add(LogEntry{Timestamp: "1", Application: "app1"})
	rb.Add(LogEntry{Timestamp: "2", Application: "app2"})
	rb.Add(LogEntry{Timestamp: "3", Application: "app3"})

	if rb.Len() != 3 {
		t.Errorf("expected len 3, got %d", rb.Len())
	}

	entries := rb.SliceChrono()
	if entries[0].Timestamp != "1" || entries[1].Timestamp != "2" || entries[2].Timestamp != "3" {
		t.Errorf("entries not in chronological order: %v", entries)
	}
}

func TestRingBuffer_Add_OverCapacity(t *testing.T) {
	rb := newRingBuffer(3)

	rb.Add(LogEntry{Timestamp: "1", Application: "app1"})
	rb.Add(LogEntry{Timestamp: "2", Application: "app2"})
	rb.Add(LogEntry{Timestamp: "3", Application: "app3"})
	rb.Add(LogEntry{Timestamp: "4", Application: "app4"}) // Overwrites "1"
	rb.Add(LogEntry{Timestamp: "5", Application: "app5"}) // Overwrites "2"

	if rb.Len() != 3 {
		t.Errorf("expected len 3, got %d", rb.Len())
	}

	entries := rb.SliceChrono()
	// Should have 3, 4, 5 (oldest to newest)
	if entries[0].Timestamp != "3" {
		t.Errorf("expected first entry timestamp '3', got '%s'", entries[0].Timestamp)
	}
	if entries[1].Timestamp != "4" {
		t.Errorf("expected second entry timestamp '4', got '%s'", entries[1].Timestamp)
	}
	if entries[2].Timestamp != "5" {
		t.Errorf("expected third entry timestamp '5', got '%s'", entries[2].Timestamp)
	}
}

func TestRingBuffer_Empty(t *testing.T) {
	rb := newRingBuffer(5)

	if rb.Len() != 0 {
		t.Errorf("expected len 0, got %d", rb.Len())
	}

	entries := rb.SliceChrono()
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestRingBuffer_ZeroCapacity(t *testing.T) {
	rb := newRingBuffer(0)

	// Should not panic
	rb.Add(LogEntry{Timestamp: "1", Application: "app1"})

	if rb.Len() != 0 {
		t.Errorf("expected len 0 for zero-capacity buffer, got %d", rb.Len())
	}
}

func TestRingBuffer_WrapAround(t *testing.T) {
	rb := newRingBuffer(4)

	// Add 6 entries to a buffer of 4
	for i := 1; i <= 6; i++ {
		rb.Add(LogEntry{Timestamp: string(rune('0' + i)), Application: "app"})
	}

	entries := rb.SliceChrono()
	// Should have entries 3, 4, 5, 6
	expected := []string{"3", "4", "5", "6"}
	for i, e := range entries {
		if e.Timestamp != expected[i] {
			t.Errorf("entry %d: expected timestamp '%s', got '%s'", i, expected[i], e.Timestamp)
		}
	}
}
