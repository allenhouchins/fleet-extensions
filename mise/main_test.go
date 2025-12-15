package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectMiseInstalls_ValidStructure(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()

	// Create tool/version directories
	goPath := filepath.Join(tmpDir, "go", "1.21.0")
	if err := os.MkdirAll(goPath, 0755); err != nil {
		t.Fatalf("failed to create go directory: %v", err)
	}

	nodePath := filepath.Join(tmpDir, "node", "20.10.0")
	if err := os.MkdirAll(nodePath, 0755); err != nil {
		t.Fatalf("failed to create node directory: %v", err)
	}

	pythonPath1 := filepath.Join(tmpDir, "python", "3.11.0")
	pythonPath2 := filepath.Join(tmpDir, "python", "3.12.0")
	if err := os.MkdirAll(pythonPath1, 0755); err != nil {
		t.Fatalf("failed to create python 3.11 directory: %v", err)
	}
	if err := os.MkdirAll(pythonPath2, 0755); err != nil {
		t.Fatalf("failed to create python 3.12 directory: %v", err)
	}

	installs, err := collectMiseInstalls(tmpDir)
	if err != nil {
		t.Fatalf("collectMiseInstalls error: %v", err)
	}

	if len(installs) != 4 {
		t.Errorf("expected 4 installs, got %d", len(installs))
	}

	// Check that we have the expected tools
	tools := make(map[string][]string)
	for _, install := range installs {
		tools[install.Tool] = append(tools[install.Tool], install.Version)
	}

	if len(tools["go"]) != 1 || tools["go"][0] != "1.21.0" {
		t.Errorf("expected go 1.21.0, got %v", tools["go"])
	}

	if len(tools["node"]) != 1 || tools["node"][0] != "20.10.0" {
		t.Errorf("expected node 20.10.0, got %v", tools["node"])
	}

	if len(tools["python"]) != 2 {
		t.Errorf("expected 2 python versions, got %d", len(tools["python"]))
	}
}

func TestCollectMiseInstalls_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	installs, err := collectMiseInstalls(tmpDir)
	if err != nil {
		t.Fatalf("collectMiseInstalls error: %v", err)
	}

	if len(installs) != 0 {
		t.Errorf("expected 0 installs, got %d", len(installs))
	}
}

func TestCollectMiseInstalls_NonExistentDirectory(t *testing.T) {
	installs, err := collectMiseInstalls("/nonexistent/path/mise/installs")
	if err != nil {
		t.Fatalf("collectMiseInstalls should not error on nonexistent path: %v", err)
	}

	if len(installs) != 0 {
		t.Errorf("expected 0 installs, got %d", len(installs))
	}
}

func TestCollectMiseInstalls_IgnoresFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a tool directory with version
	goPath := filepath.Join(tmpDir, "go", "1.21.0")
	if err := os.MkdirAll(goPath, 0755); err != nil {
		t.Fatalf("failed to create go directory: %v", err)
	}

	// Create a file at the tool level (should be ignored)
	filePath := filepath.Join(tmpDir, "somefile.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	// Create a file at the version level (should be ignored)
	versionFilePath := filepath.Join(tmpDir, "go", "VERSION")
	if err := os.WriteFile(versionFilePath, []byte("1.21.0"), 0644); err != nil {
		t.Fatalf("failed to create version file: %v", err)
	}

	installs, err := collectMiseInstalls(tmpDir)
	if err != nil {
		t.Fatalf("collectMiseInstalls error: %v", err)
	}

	if len(installs) != 1 {
		t.Errorf("expected 1 install (files should be ignored), got %d", len(installs))
	}

	if installs[0].Tool != "go" || installs[0].Version != "1.21.0" {
		t.Errorf("expected go 1.21.0, got %s %s", installs[0].Tool, installs[0].Version)
	}
}

func TestCollectMiseInstalls_InstallPath(t *testing.T) {
	tmpDir := t.TempDir()

	goPath := filepath.Join(tmpDir, "go", "1.21.0")
	if err := os.MkdirAll(goPath, 0755); err != nil {
		t.Fatalf("failed to create go directory: %v", err)
	}

	installs, err := collectMiseInstalls(tmpDir)
	if err != nil {
		t.Fatalf("collectMiseInstalls error: %v", err)
	}

	if len(installs) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs))
	}

	expectedPath := filepath.Join(tmpDir, "go", "1.21.0")
	if installs[0].InstallPath != expectedPath {
		t.Errorf("expected install path '%s', got '%s'", expectedPath, installs[0].InstallPath)
	}
}

func TestCollectMiseInstalls_InstalledAtTimestamp(t *testing.T) {
	tmpDir := t.TempDir()

	goPath := filepath.Join(tmpDir, "go", "1.21.0")
	if err := os.MkdirAll(goPath, 0755); err != nil {
		t.Fatalf("failed to create go directory: %v", err)
	}

	installs, err := collectMiseInstalls(tmpDir)
	if err != nil {
		t.Fatalf("collectMiseInstalls error: %v", err)
	}

	if len(installs) != 1 {
		t.Fatalf("expected 1 install, got %d", len(installs))
	}

	// InstalledAt should be non-zero (recent)
	if installs[0].InstalledAt.IsZero() {
		t.Error("expected non-zero InstalledAt timestamp")
	}
}

func TestMiseInstallsColumns(t *testing.T) {
	columns := miseInstallsColumns()

	expectedColumns := []string{"tool", "version", "install_path", "installed_at"}

	if len(columns) != len(expectedColumns) {
		t.Errorf("expected %d columns, got %d", len(expectedColumns), len(columns))
	}

	for i, col := range columns {
		if col.Name != expectedColumns[i] {
			t.Errorf("column %d: expected name '%s', got '%s'", i, expectedColumns[i], col.Name)
		}
	}
}

func TestGetMiseInstallsPath_MiseDataDir(t *testing.T) {
	// Save and restore env vars
	origMiseDataDir := os.Getenv("MISE_DATA_DIR")
	origXdgDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("MISE_DATA_DIR", origMiseDataDir)
		os.Setenv("XDG_DATA_HOME", origXdgDataHome)
	}()

	os.Setenv("MISE_DATA_DIR", "/custom/mise/data")
	os.Unsetenv("XDG_DATA_HOME")

	path := getMiseInstallsPath()
	expected := "/custom/mise/data/installs"
	if path != expected {
		t.Errorf("expected '%s', got '%s'", expected, path)
	}
}

func TestGetMiseInstallsPath_XdgDataHome(t *testing.T) {
	// Save and restore env vars
	origMiseDataDir := os.Getenv("MISE_DATA_DIR")
	origXdgDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("MISE_DATA_DIR", origMiseDataDir)
		os.Setenv("XDG_DATA_HOME", origXdgDataHome)
	}()

	os.Unsetenv("MISE_DATA_DIR")
	os.Setenv("XDG_DATA_HOME", "/custom/xdg/data")

	path := getMiseInstallsPath()
	expected := "/custom/xdg/data/mise/installs"
	if path != expected {
		t.Errorf("expected '%s', got '%s'", expected, path)
	}
}

func TestGetMiseInstallsPath_Default(t *testing.T) {
	// Save and restore env vars
	origMiseDataDir := os.Getenv("MISE_DATA_DIR")
	origXdgDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("MISE_DATA_DIR", origMiseDataDir)
		os.Setenv("XDG_DATA_HOME", origXdgDataHome)
	}()

	os.Unsetenv("MISE_DATA_DIR")
	os.Unsetenv("XDG_DATA_HOME")

	path := getMiseInstallsPath()
	// Should end with .local/share/mise/installs
	if !strings.HasSuffix(path, filepath.Join(".local", "share", "mise", "installs")) {
		t.Errorf("expected path to end with '.local/share/mise/installs', got '%s'", path)
	}
}

func TestGetMiseInstallsPath_MiseDataDirTakesPriority(t *testing.T) {
	// Save and restore env vars
	origMiseDataDir := os.Getenv("MISE_DATA_DIR")
	origXdgDataHome := os.Getenv("XDG_DATA_HOME")
	defer func() {
		os.Setenv("MISE_DATA_DIR", origMiseDataDir)
		os.Setenv("XDG_DATA_HOME", origXdgDataHome)
	}()

	// Set both, MISE_DATA_DIR should take priority
	os.Setenv("MISE_DATA_DIR", "/mise/priority")
	os.Setenv("XDG_DATA_HOME", "/xdg/fallback")

	path := getMiseInstallsPath()
	expected := "/mise/priority/installs"
	if path != expected {
		t.Errorf("MISE_DATA_DIR should take priority, expected '%s', got '%s'", expected, path)
	}
}
