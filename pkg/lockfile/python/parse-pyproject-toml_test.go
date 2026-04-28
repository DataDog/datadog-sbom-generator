package python_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22),
		},
		{
			Name: "flask", Version: "2.3.2", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 6, 6, 5, 20), NameLocation: posPtr(path, 6, 6, 6, 11), VersionLocation: posPtr(path, 6, 6, 13, 18),
		},
		{
			Name: "boto3", Version: "1.26.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 9, 9, 5, 21), NameLocation: posPtr(path, 9, 9, 6, 11), VersionLocation: posPtr(path, 9, 9, 13, 19),
		},
	})
}

func TestParsePyProjectTOML_PEP621_UnpinnedSkipped(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/no-pinned/pyproject.toml"))

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

// ============================================================================
// [project.optional-dependencies]
// ============================================================================

func TestParsePyProjectTOML_PEP621_OptionalDeps(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/pep621-optional/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22),
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 10, 10, 5, 21), NameLocation: posPtr(path, 10, 10, 6, 12), VersionLocation: posPtr(path, 10, 10, 14, 19),
		},
		{
			Name: "mypy", Version: "1.5.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 11, 11, 5, 19), NameLocation: posPtr(path, 11, 11, 6, 10), VersionLocation: posPtr(path, 11, 11, 12, 17),
		},
		{
			Name: "sphinx", Version: "7.1.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"docs"},
			BlockLocation: pos(path, 14, 14, 5, 21), NameLocation: posPtr(path, 14, 14, 6, 12), VersionLocation: posPtr(path, 14, 14, 14, 19),
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22),
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 12, 12, 5, 21), NameLocation: posPtr(path, 12, 12, 6, 12), VersionLocation: posPtr(path, 12, 12, 14, 19),
		},
		{
			Name: "ruff", Version: "0.1.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 13, 13, 5, 19), NameLocation: posPtr(path, 13, 13, 6, 10), VersionLocation: posPtr(path, 13, 13, 12, 17),
		},
		{
			Name: "hypothesis", Version: "6.100.0", PackageManager: models.Uv, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 17, 17, 5, 27), NameLocation: posPtr(path, 17, 17, 6, 16), VersionLocation: posPtr(path, 17, 17, 18, 25),
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
	// python version constraint must be skipped; unpinned numpy (^) must be skipped
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 11, 11, 1, 22), NameLocation: posPtr(path, 11, 11, 1, 9), VersionLocation: posPtr(path, 11, 11, 13, 21),
		},
		{
			Name: "flask", Version: "2.3.2", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 12, 12, 1, 18), NameLocation: posPtr(path, 12, 12, 1, 6), VersionLocation: posPtr(path, 12, 12, 10, 17),
		},
		{
			Name: "boto3", Version: "1.26.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 13, 13, 1, 17), NameLocation: posPtr(path, 13, 13, 1, 6), VersionLocation: posPtr(path, 13, 13, 10, 16),
		},
	})
}

func TestParsePyProjectTOML_Poetry_GroupDeps(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/poetry-groups/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 11, 11, 1, 22), NameLocation: posPtr(path, 11, 11, 1, 9), VersionLocation: posPtr(path, 11, 11, 13, 21),
		},
		{
			Name: "black", Version: "23.1.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"dev"},
			BlockLocation: pos(path, 14, 14, 1, 19), NameLocation: posPtr(path, 14, 14, 1, 6), VersionLocation: posPtr(path, 14, 14, 10, 18),
		},
		{
			Name: "pytest", Version: "7.4.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 17, 17, 1, 19), NameLocation: posPtr(path, 17, 17, 1, 7), VersionLocation: posPtr(path, 17, 17, 11, 18),
		},
		{
			Name: "pytest-cov", Version: "4.1.0", PackageManager: models.Poetry, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"test"},
			BlockLocation: pos(path, 18, 18, 1, 35), NameLocation: posPtr(path, 18, 18, 1, 11), VersionLocation: posPtr(path, 18, 18, 26, 33),
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePyProjectTOML_SuppressedByPoetryLock(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/with-poetry-lock/pyproject.toml"))

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

// ============================================================================
// Parenthesized specifiers
// ============================================================================

func TestParsePyProjectTOML_PEP621_ParenthesizedPin(t *testing.T) {
	t.Parallel()

	path := fixturePath(t, "../fixtures/pyproject-toml-extractor/pep621-parens/pyproject.toml")
	packages, err := python.ParsePyProjectTOML(path)

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod"},
			BlockLocation: pos(path, 5, 5, 5, 27), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 18, 24),
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name: "requests", Version: "2.28.0", PackageManager: models.Unknown, Ecosystem: models.EcosystemPyPI, IsDirect: true, DepGroups: []string{"prod", "dev"},
			BlockLocation: pos(path, 5, 5, 5, 24), NameLocation: posPtr(path, 5, 5, 6, 14), VersionLocation: posPtr(path, 5, 5, 16, 22),
		},
	})
}

// ============================================================================
// Error cases
// ============================================================================

func TestParsePyProjectTOML_InvalidTOML(t *testing.T) {
	t.Parallel()

	_, err := python.ParsePyProjectTOML(fixturePath(t, "../fixtures/pyproject-toml-extractor/invalid/pyproject.toml"))

	testutil.ExpectErrContaining(t, err, "could not extract from")
}
