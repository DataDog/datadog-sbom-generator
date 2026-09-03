package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testFilePerms creates temporary config files readable and writable only by the current user.
const testFilePerms = 0o600

func TestReadLocalConfigContentsYAML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - vendor/**\n"

	if err := os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(content), testFilePerms); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	got, err := readLocalConfigContents(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != content {
		t.Fatalf("got %q, want %q", got, content)
	}
}

func TestReadLocalConfigContentsYML(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := "schema-version: v1.1\n"

	if err := os.WriteFile(filepath.Join(dir, "code-security.datadog.yml"), []byte(content), testFilePerms); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	got, err := readLocalConfigContents(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != content {
		t.Fatalf("got %q, want %q", got, content)
	}
}

func TestReadLocalConfigContentsNotFound(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := readLocalConfigContents(dir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestParseValid(t *testing.T) {
	t.Parallel()

	contents := "schema-version: v1.7\nsca:\n  ignore-paths:\n    - src/domains/bar/*\n    - \"**/*test.go\"\n  ignore-ecosystems:\n    - npm\n    - Go\n"

	cfg, err := parseUnifiedConfig(contents)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.SchemaVersion != "v1.7" {
		t.Fatalf("SchemaVersion = %q, want %q", cfg.SchemaVersion, "v1.7")
	}

	if len(cfg.SCA.IgnorePaths) != 2 {
		t.Fatalf("IgnorePaths length = %d, want 2", len(cfg.SCA.IgnorePaths))
	}

	if cfg.SCA.IgnorePaths[0] != "src/domains/bar/*" {
		t.Fatalf("IgnorePaths[0] = %q, want %q", cfg.SCA.IgnorePaths[0], "src/domains/bar/*")
	}

	if cfg.SCA.IgnorePaths[1] != "**/*test.go" {
		t.Fatalf("IgnorePaths[1] = %q, want %q", cfg.SCA.IgnorePaths[1], "**/*test.go")
	}

	if len(cfg.SCA.IgnoreEcosystems) != 2 {
		t.Fatalf("IgnoreEcosystems length = %d, want 2", len(cfg.SCA.IgnoreEcosystems))
	}

	if cfg.SCA.IgnoreEcosystems[0] != "npm" || cfg.SCA.IgnoreEcosystems[1] != "Go" {
		t.Fatalf("IgnoreEcosystems = %v, want [npm Go]", cfg.SCA.IgnoreEcosystems)
	}
}

func TestParseNoSCASection(t *testing.T) {
	t.Parallel()

	contents := "schema-version: v1.1\n"

	cfg, err := parseUnifiedConfig(contents)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.SCA.IgnorePaths) != 0 {
		t.Fatalf("IgnorePaths length = %d, want 0", len(cfg.SCA.IgnorePaths))
	}

	if len(cfg.SCA.IgnoreEcosystems) != 0 {
		t.Fatalf("IgnoreEcosystems length = %d, want 0", len(cfg.SCA.IgnoreEcosystems))
	}
}

func TestParseMalformedYAML(t *testing.T) {
	t.Parallel()

	contents := ":\n  invalid: [yaml\n"

	_, err := parseUnifiedConfig(contents)
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}
