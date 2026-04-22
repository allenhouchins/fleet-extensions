package main

import (
	"reflect"
	"testing"
)

func TestParseSoftwareUpdateList(t *testing.T) {
	sample := `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: MotionContent-1.0
	Title: Motion Supplemental Content, Version: 1.0, Size: 1091206KiB, Recommended: YES, 
* Label: ProVideoFormats-3.1
	Title: Pro Video Formats, Version: 3.1, Size: 9779KiB, Recommended: YES, 
* Label: Command Line Tools for Xcode 26.4-26.4.1
	Title: Command Line Tools for Xcode 26.4, Version: 26.4.1, Size: 920104KiB, Recommended: YES, 
* Label: macOS Tahoe 26.4.1-25E253
	Title: macOS Tahoe 26.4.1, Version: 26.4.1, Size: 6983632KiB, Recommended: YES, Action: restart, 
`

	want := []map[string]string{
		{
			"label": "MotionContent-1.0", "title": "Motion Supplemental Content", "version": "1.0",
			"size": "1091206KiB", "recommended": "YES", "action": "",
		},
		{
			"label": "ProVideoFormats-3.1", "title": "Pro Video Formats", "version": "3.1",
			"size": "9779KiB", "recommended": "YES", "action": "",
		},
		{
			"label": "Command Line Tools for Xcode 26.4-26.4.1", "title": "Command Line Tools for Xcode 26.4", "version": "26.4.1",
			"size": "920104KiB", "recommended": "YES", "action": "",
		},
		{
			"label": "macOS Tahoe 26.4.1-25E253", "title": "macOS Tahoe 26.4.1", "version": "26.4.1",
			"size": "6983632KiB", "recommended": "YES", "action": "restart",
		},
	}

	got := parseSoftwareUpdateList(sample)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSoftwareUpdateList() mismatch\n got: %#v\nwant: %#v", got, want)
	}
}

func TestParseSoftwareUpdateList_NoUpdates(t *testing.T) {
	sample := `Software Update Tool

Finding available software
Software Update found the following new or updated software:

`
	if got := parseSoftwareUpdateList(sample); len(got) != 0 {
		t.Fatalf("expected no rows, got %#v", got)
	}
}
