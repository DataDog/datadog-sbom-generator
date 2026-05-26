package sbomgen

import (
	"encoding/json"
	"testing"
)

func TestGenerateSBOM_HappyPath(t *testing.T) {
	t.Parallel()

	// Use a local testdata fixture with a single Cargo.lock dependency
	dirs := []string{"testdata"}
	opts := DefaultOptions()

	result, err := GenerateSBOM(dirs, opts)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("expected non-empty SBOM output")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("expected valid JSON output, got parse error: %v", err)
	}

	// Verify CycloneDX structure
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat 'CycloneDX', got %v", parsed["bomFormat"])
	}

	// Verify components exist (the fixture has at least one package)
	components, ok := parsed["components"].([]interface{})
	if !ok || len(components) == 0 {
		t.Error("expected at least one component in the SBOM")
	}
}

func TestGenerateSBOM_EmptyDirs(t *testing.T) {
	t.Parallel()

	_, err := GenerateSBOM([]string{}, DefaultOptions())
	if err == nil {
		t.Fatal("expected error for empty dirs slice, got nil")
	}
}

func TestDefaultOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()

	if !opts.Recursive {
		t.Error("expected Recursive to be true by default")
	}

	if opts.ExcludePaths == nil {
		t.Error("expected ExcludePaths to be non-nil")
	}

	if len(opts.ExcludePaths) != 0 {
		t.Errorf("expected ExcludePaths to be empty, got %v", opts.ExcludePaths)
	}
}
