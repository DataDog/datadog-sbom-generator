package python_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
)

var pyprojectTOMLMatcher = python.PyprojectTOMLMatcher{}

func TestPyprojectTomlMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/does-not-exist/poetry.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pyprojectTOMLMatcher.GetSourceFile(lockFile)
	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestPyprojectTomlMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pyproject-toml/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"pyproject.toml"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "poetry.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pyprojectTOMLMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestPyprojectTomlMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/one-package/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 10, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestPyprojectTomlMatcher_Match_OnePackageDev(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/one-package-dev/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 10, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
	})
}

func TestPyprojectTomlMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/transitive/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
		},
		{
			Name:           "proto-plus",
			PackageManager: models.Poetry,
		},
		{
			Name:           "protobuf",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 10, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "proto-plus",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 18},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 15, End: 17},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "protobuf",
			PackageManager: models.Poetry,
		},
	})
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArray is a regression test for a bug where
// switching the matcher from substring search to exact "key = value" matching broke PEP 621
// dependency-array entries (pyproject.toml `dependencies = [...]`), since array items like
// `"requests==2.28.0",` have no assignment operator: they were silently skipped, so PEP 621
// direct dependencies lost their manifest location and IsDirect flag. This covers a pinned
// version (`==`), a range operator (`>=`), and a bare unversioned entry.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArray(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "requests",
			PackageManager: models.Poetry,
		},
		{
			Name:           "flask",
			PackageManager: models.Poetry,
		},
		{
			Name:           "scipy",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "requests",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 24},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 14},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "flask",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 18},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 11},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "scipy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 5, End: 13},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 6, End: 11},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInline is a regression test for a bug where
// a PEP 621 dependency array declared inline on a single line, e.g.
// `dependencies = ["requests>=2.32", "flask==2.0"]`, was never matched: pep621ArrayItemName
// required the entire physical line to be a single quoted token, so this line fell through to the
// "key = value" path and extracted "dependencies" as the key instead of the package names,
// leaving every package on the line without a manifest location and IsDirect=false.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInline(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-inline-array/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "requests",
			PackageManager: models.Poetry,
		},
		{
			Name:           "flask",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "requests",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 48},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 18, End: 26},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "flask",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 48},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 36, End: 41},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}
