package python_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func fixturePath(t *testing.T, rel string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("could not get working directory: %v", err)
	}

	return filepath.FromSlash(filepath.Join(dir, rel))
}

func pos(filename string, lineStart, lineEnd, colStart, colEnd int) models.FilePosition {
	return models.FilePosition{
		Line:     models.Position{Start: lineStart, End: lineEnd},
		Column:   models.Position{Start: colStart, End: colEnd},
		Filename: filename,
	}
}

func posPtr(filename string, lineStart, lineEnd, colStart, colEnd int) *models.FilePosition {
	p := pos(filename, lineStart, lineEnd, colStart, colEnd)
	return &p
}

// ============================================================================
// ShouldExtract
// ============================================================================

func TestPyProjectTOMLExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "empty", path: "", want: false},
		{name: "plain", path: "pyproject.toml", want: true},
		{name: "absolute", path: "/path/to/pyproject.toml", want: true},
		{name: "relative", path: "../../pyproject.toml", want: true},
		{name: "in-path", path: "/path/with/pyproject.toml/in/middle", want: false},
		{name: "invalid-suffix", path: "pyproject.toml.bak", want: false},
		{name: "invalid-prefix", path: "old.pyproject.toml", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ext := python.PyProjectTOMLExtractor{}
			if got := ext.ShouldExtract(tt.path); got != tt.want {
				t.Errorf("ShouldExtract(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ============================================================================
// PEP 621 [project] dependencies
// ============================================================================

func TestParsePyProjectTOML_PEP621_PinnedExtracted(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/pep621-pinned/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "flask", Version: "2.3.2", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 6, 6, 5, 20), NameLocation: posPtr(path, 6, 6, 6, 11), VersionLocation: posPtr(path, 6, 6, 13, 18), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "numpy", VersionRange: ">=1.24", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 7, 7, 5, 19), NameLocation: posPtr(path, 7, 7, 6, 11), VersionLocation: posPtr(path, 7, 7, 11, 17), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "boto3", Version: "1.26.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 9, 9, 5, 21), NameLocation: posPtr(path, 9, 9, 6, 11), VersionLocation: posPtr(path, 9, 9, 13, 19), LocationRole: models.LocationRoleManifest,
		},
	})
}

func TestParsePyProjectTOML_PEP621_RangesExtractedAndUnversionedSkipped(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/no-pinned/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", VersionRange: ">=2.28", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 22), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 14, 20), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "flask", VersionRange: "~=2.3", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 6, 6, 5, 18), NameLocation: posPtr(path, 6, 6, 6, 11), VersionLocation: posPtr(path, 6, 6, 11, 16), LocationRole: models.LocationRoleManifest,
		},
	})
}

// ============================================================================
// [project.optional-dependencies]
// ============================================================================

func TestParsePyProjectTOML_PEP621_OptionalDeps(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/pep621-optional/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 10, 10, 5, 21), NameLocation: posPtr(path, 10, 10, 6, 12), VersionLocation: posPtr(path, 10, 10, 14, 19), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "mypy", Version: "1.5.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 11, 11, 5, 19), NameLocation: posPtr(path, 11, 11, 6, 10), VersionLocation: posPtr(path, 11, 11, 12, 17), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "sphinx", Version: "7.1.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"docs"},
			BlockLocation: pos(path, 14, 14, 5, 21), NameLocation: posPtr(path, 14, 14, 6, 12), VersionLocation: posPtr(path, 14, 14, 14, 19), LocationRole: models.LocationRoleManifest,
		},
	})
}

// ============================================================================
// [dependency-groups] (PEP 735 / uv)
// ============================================================================

func TestParsePyProjectTOML_DependencyGroups_PinnedExtracted(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/uv-dependency-groups/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 12, 12, 5, 21), NameLocation: posPtr(path, 12, 12, 6, 12), VersionLocation: posPtr(path, 12, 12, 14, 19), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "ruff", Version: "0.1.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 13, 13, 5, 19), NameLocation: posPtr(path, 13, 13, 6, 10), VersionLocation: posPtr(path, 13, 13, 12, 17), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "hypothesis", Version: "6.100.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 17, 17, 5, 27), NameLocation: posPtr(path, 17, 17, 6, 16), VersionLocation: posPtr(path, 17, 17, 18, 25), LocationRole: models.LocationRoleManifest,
		},
	})
}

// ============================================================================
// [tool.poetry] detection
// ============================================================================

func TestParsePyProjectTOML_Poetry_PinnedExtracted(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/poetry-pinned/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	// python version constraint must be skipped; the numpy range is preserved for reducer resolution
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 11, 11, 1, 22), NameLocation: posPtr(path, 11, 11, 1, 9), VersionLocation: posPtr(path, 11, 11, 13, 21), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "flask", Version: "2.3.2", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 12, 12, 1, 18), NameLocation: posPtr(path, 12, 12, 1, 6), VersionLocation: posPtr(path, 12, 12, 10, 17), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "boto3", Version: "1.26.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 13, 13, 1, 17), NameLocation: posPtr(path, 13, 13, 1, 6), VersionLocation: posPtr(path, 13, 13, 10, 16), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "numpy", VersionRange: "^1.24", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 14, 14, 1, 16), NameLocation: posPtr(path, 14, 14, 1, 6), VersionLocation: posPtr(path, 14, 14, 10, 15), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "scipy", VersionRange: "1.*", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 15, 15, 1, 14), NameLocation: posPtr(path, 15, 15, 1, 6), VersionLocation: posPtr(path, 15, 15, 10, 13), LocationRole: models.LocationRoleManifest,
		},
	})
}

func TestParsePyProjectTOML_Poetry_GroupDeps(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/poetry-groups/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 11, 11, 1, 22), NameLocation: posPtr(path, 11, 11, 1, 9), VersionLocation: posPtr(path, 11, 11, 13, 21), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "black", Version: "23.1.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 14, 14, 1, 19), NameLocation: posPtr(path, 14, 14, 1, 6), VersionLocation: posPtr(path, 14, 14, 10, 18), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 17, 17, 1, 19), NameLocation: posPtr(path, 17, 17, 1, 7), VersionLocation: posPtr(path, 17, 17, 11, 18), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "pytest-cov", Version: "4.1.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 18, 18, 1, 35), NameLocation: posPtr(path, 18, 18, 1, 11), VersionLocation: posPtr(path, 18, 18, 26, 33), LocationRole: models.LocationRoleManifest,
		},
	})
}

// ============================================================================
// Lock file guard
// ============================================================================

func TestParsePyProjectTOML_SupressedByUvLock(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/with-uv-lock/pyproject.toml"))

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParsePyProjectTOML_SuppressedByPoetryLock(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/with-poetry-lock/pyproject.toml"))

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

// ============================================================================
// Parenthesized specifiers
// ============================================================================

func TestParsePyProjectTOML_PEP621_ParenthesizedPin(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/pep621-parens/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 27), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 18, 24), LocationRole: models.LocationRoleManifest,
		},
	})
}

// ============================================================================
// Group merging
// ============================================================================

func TestParsePyProjectTOML_MergesGroupsForDuplicatePackage(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/duplicate-groups/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod", "dev"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22), LocationRole: models.LocationRoleManifest,
		},
	})
}

func TestParsePyProjectTOML_ConflictingRangesAreSourceOrderedAndLogged(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	r := reporter.NewCycloneDXReporterWithPretty(os.Stdout, &logs, reporter.WarnLevel, true)

	dir := t.TempDir()
	path := filepath.Join(dir, "pyproject.toml")
	content := `[project]
name = "my-app"
version = "1.0.0"
dependencies = [
    "requests>=1,<2",
    "flask>=2",
]

[project.optional-dependencies]
dev = [
    "requests>=2,<3",
]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("could not write pyproject fixture: %v", err)
	}

	ctx := extractor.ScanContext{Reporter: r}
	packages, err := extractor.ExtractFromFileWithContext(path, python.PyProjectExtractor, ctx)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name: "requests", VersionRange: ">=1,<2", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 22), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 14, 20), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "flask", VersionRange: ">=2", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 6, 6, 5, 16), NameLocation: posPtr(path, 6, 6, 6, 11), VersionLocation: posPtr(path, 6, 6, 11, 14), LocationRole: models.LocationRoleManifest,
		},
		{
			Name: "requests", VersionRange: ">=2,<3", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, RequiresTransitiveEnrichment: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 11, 11, 5, 22), NameLocation: posPtr(path, 11, 11, 6, 14), VersionLocation: posPtr(path, 11, 11, 14, 20), LocationRole: models.LocationRoleManifest,
		},
	})

	if len(packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(packages))
	}
	if packages[0].Name != "requests" || packages[0].VersionRange != ">=1,<2" {
		t.Fatalf("expected first package to be earliest requests range, got %s %q", packages[0].Name, packages[0].VersionRange)
	}
	if !strings.Contains(logs.String(), `Multiple pyproject version ranges for dependency "requests"`) {
		t.Fatalf("expected conflicting range log, got %q", logs.String())
	}
}

// ============================================================================
// Error cases
// ============================================================================

func TestParsePyProjectTOML_InvalidTOML(t *testing.T) {
	t.Parallel()

	_, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/invalid/pyproject.toml"))

	testutil.ExpectErrContaining(t, err, "could not extract from")
}
