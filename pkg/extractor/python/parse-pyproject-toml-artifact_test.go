package python_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestPyProjectTOMLExtractor_GetArtifact(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a pyproject.toml with a project name
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	err := os.WriteFile(pyprojectPath, []byte(`[project]
name = "my-awesome-lib"
version = "1.0.0"
`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	f, err := extractor.OpenLocalDepFile(pyprojectPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact, err := python.PyProjectExtractor.GetArtifact(f, extractor.ScanContext{ExtractArtifactIds: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if artifact == nil {
		t.Fatal("expected artifact, got nil")
	}
	if artifact.Name != "my-awesome-lib" {
		t.Errorf("expected name 'my-awesome-lib', got %q", artifact.Name)
	}
	if artifact.Filename != pyprojectPath {
		t.Errorf("expected filename %q, got %q", pyprojectPath, artifact.Filename)
	}
	if artifact.Ecosystem != models.EcosystemPyPI {
		t.Errorf("expected ecosystem %q, got %q", models.EcosystemPyPI, artifact.Ecosystem)
	}
}

func TestPyProjectTOMLExtractor_GetArtifact_PoetryName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Poetry layout: name is under [tool.poetry], not [project]
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	err := os.WriteFile(pyprojectPath, []byte(`[tool.poetry]
name = "my-poetry-lib"
version = "2.0.0"
`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	f, err := extractor.OpenLocalDepFile(pyprojectPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact, err := python.PyProjectExtractor.GetArtifact(f, extractor.ScanContext{ExtractArtifactIds: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if artifact == nil {
		t.Fatal("expected artifact from [tool.poetry].name, got nil")
	}
	if artifact.Name != "my-poetry-lib" {
		t.Errorf("expected name 'my-poetry-lib', got %q", artifact.Name)
	}
}

func TestPyProjectTOMLExtractor_GetArtifact_NoName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a pyproject.toml without a project name
	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	err := os.WriteFile(pyprojectPath, []byte(`[project]
version = "1.0.0"
`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	f, err := extractor.OpenLocalDepFile(pyprojectPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	artifact, err := python.PyProjectExtractor.GetArtifact(f, extractor.ScanContext{ExtractArtifactIds: true})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if artifact != nil {
		t.Errorf("expected nil artifact, got %+v", artifact)
	}
}

func TestPyProjectTOMLExtractor_GetArtifact_ExtractArtifactIdsDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	pyprojectPath := filepath.Join(dir, "pyproject.toml")
	err := os.WriteFile(pyprojectPath, []byte(`[project]
name = "my-lib"
`), 0600)
	if err != nil {
		t.Fatal(err)
	}

	f, err := extractor.OpenLocalDepFile(pyprojectPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// ExtractArtifactIds is false — should return nil
	artifact, err := python.PyProjectExtractor.GetArtifact(f, extractor.ScanContext{ExtractArtifactIds: false})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if artifact != nil {
		t.Errorf("expected nil artifact when ExtractArtifactIds is false, got %+v", artifact)
	}
}

func TestPyProjectTOMLExtractor_GetArtifact_NormalizesName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tomlName string
		expected string
	}{
		{
			name:     "underscores to hyphens",
			tomlName: "my_package",
			expected: "my-package",
		},
		{
			name:     "dots to hyphens",
			tomlName: "my.package",
			expected: "my-package",
		},
		{
			name:     "uppercase to lowercase",
			tomlName: "My-Package",
			expected: "my-package",
		},
		{
			name:     "mixed separators and case",
			tomlName: "My_Cool.Package",
			expected: "my-cool-package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			pyprojectPath := filepath.Join(dir, "pyproject.toml")
			err := os.WriteFile(pyprojectPath, []byte("[project]\nname = \""+tt.tomlName+"\"\n"), 0600)
			if err != nil {
				t.Fatal(err)
			}

			f, err := extractor.OpenLocalDepFile(pyprojectPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			artifact, err := python.PyProjectExtractor.GetArtifact(f, extractor.ScanContext{ExtractArtifactIds: true})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if artifact == nil {
				t.Fatal("expected artifact, got nil")
			}
			if artifact.Name != tt.expected {
				t.Errorf("expected name %q, got %q", tt.expected, artifact.Name)
			}
		})
	}
}
