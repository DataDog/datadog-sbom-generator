package python_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
)

var pyprojectTOMLMatcher = python.PyprojectTOMLMatcher{}

func TestPyprojectTomlMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/does-not-exist/poetry.lock")
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

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "poetry.lock")
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

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/one-package/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
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

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/one-package-dev/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
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

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/transitive/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
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
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 19},
				Filename: sourceFile.Path(),
			},
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

func TestPyprojectTomlMatcher_Match_PEP621_Basic(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-basic/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "flask",
			PackageManager: models.Uv,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "flask",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 19},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 16},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestPyprojectTomlMatcher_Match_PEP621_Operators(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-operators/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Uv,
		},
		{
			Name:           "ray",
			PackageManager: models.Uv,
		},
		{
			Name:           "pandas",
			PackageManager: models.Uv,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 21},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "ray",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 18},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 8},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 10, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "pandas",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 5, End: 21},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 5, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 13, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestPyprojectTomlMatcher_Match_PEP621_Dev(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-dev/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Uv,
		},
		{
			Name:           "pytest",
			PackageManager: models.Uv,
		},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 21},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "pytest",
			PackageManager: models.Uv,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 5, End: 21},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 5, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 13, End: 18},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
	})
}
