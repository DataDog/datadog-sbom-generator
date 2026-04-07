package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadConfigFile_YAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - vendor/**\n"
	os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(content), 0o644)

	got, err := ReadConfigFile(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestReadConfigFile_YML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := "schema-version: v1.1\n"
	os.WriteFile(filepath.Join(dir, "code-security.datadog.yml"), []byte(content), 0o644)

	got, err := ReadConfigFile(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestReadConfigFile_YAMLTakesPrecedence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yamlContent := "yaml-file\n"
	ymlContent := "yml-file\n"
	os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(yamlContent), 0o644)
	os.WriteFile(filepath.Join(dir, "code-security.datadog.yml"), []byte(ymlContent), 0o644)

	got, err := ReadConfigFile(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != yamlContent {
		t.Errorf("got %q, want %q", got, yamlContent)
	}
}

func TestReadConfigFile_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_, err := ReadConfigFile(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}

func TestParseConfig_Valid(t *testing.T) {
	t.Parallel()
	data := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - src/domains/bar/*\n    - \"**/*test.go\"\n"

	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SchemaVersion != "v1.1" {
		t.Errorf("SchemaVersion = %q, want %q", cfg.SchemaVersion, "v1.1")
	}
	if len(cfg.SCA.IgnorePaths) != 2 {
		t.Fatalf("IgnorePaths length = %d, want 2", len(cfg.SCA.IgnorePaths))
	}
	if cfg.SCA.IgnorePaths[0] != "src/domains/bar/*" {
		t.Errorf("IgnorePaths[0] = %q, want %q", cfg.SCA.IgnorePaths[0], "src/domains/bar/*")
	}
	if cfg.SCA.IgnorePaths[1] != "**/*test.go" {
		t.Errorf("IgnorePaths[1] = %q, want %q", cfg.SCA.IgnorePaths[1], "**/*test.go")
	}
}

func TestParseConfig_NoSCASection(t *testing.T) {
	t.Parallel()
	data := "schema-version: v1.1\n"

	cfg, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.SCA.IgnorePaths) != 0 {
		t.Errorf("IgnorePaths length = %d, want 0", len(cfg.SCA.IgnorePaths))
	}
}

func TestParseConfig_MalformedYAML(t *testing.T) {
	t.Parallel()
	data := ":\n  invalid: [yaml\n"

	_, err := ParseConfig(data)
	if err == nil {
		t.Error("expected error for malformed YAML, got nil")
	}
}
