package python_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var requirementsInMatcher = python.RequirementsInMatcher{}

func TestRequirementsInMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	// generated-simple.txt has no sibling .in file
	lockFile, err := lockfile.OpenLocalDepFile("../fixtures/pip/generated-simple.txt")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := requirementsInMatcher.GetSourceFile(lockFile)
	require.NoError(t, err)
	assert.Nil(t, sourceFile)
}

func TestRequirementsInMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	lockFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.txt")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := requirementsInMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestRequirementsInMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pip/with-in-file/requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 17},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 11, End: 17},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestRequirementsInMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/pip/with-in-file/requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "certifi",
			Version:        "2024.8.30",
			PackageManager: models.Requirements,
		},
		{
			Name:           "flask",
			Version:        "3.0.3",
			PackageManager: models.Requirements,
		},
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Requirements,
		},
		{
			Name:           "typing-extensions",
			Version:        "4.13.2",
			PackageManager: models.Requirements,
		},
		{
			Name:           "urllib3",
			Version:        "2.2.3",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// NOT in .in file → untouched
			Name:           "certifi",
			Version:        "2024.8.30",
			PackageManager: models.Requirements,
		},
		{
			// Flask==3.0.3 in .in (line 4) → matched via normalized name
			Name:           "flask",
			Version:        "3.0.3",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 13},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 8, End: 13},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			// requests==2.32.3 in .in (line 2) → matched
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 17},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 11, End: 17},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			// typing_extensions>=4.0 in .in (line 3) → matched via PEP 503 normalization
			// Version 4.13.2 (from lockfile) not found in ">=4.0" → VersionLocation nil
			Name:           "typing-extensions",
			Version:        "4.13.2",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 23},
				Filename: sourceFile.Path(),
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 1, End: 18},
				Filename: sourceFile.Path(),
			},
			// VersionLocation is nil: resolved "4.13.2" not in "typing_extensions>=4.0"
			IsDirect: true,
		},
		{
			// NOT in .in file → untouched
			Name:           "urllib3",
			Version:        "2.2.3",
			PackageManager: models.Requirements,
		},
	})
}

func TestRequirementsInMatcher_Match_DuplicateNameDifferentVersions(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file-duplicate-names/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	sourceFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.0",
			PackageManager: models.Requirements,
		},
		{
			Name:           "requests",
			Version:        "3.5",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// requests==2.0 on line 1 — must not be overwritten by the line-2 entry
			Name:           "requests",
			Version:        "2.0",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 14},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcefilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 11, End: 14},
				Filename: sourcefilePath,
			},
			IsDirect: true,
		},
		{
			// requests==3.5 on line 2
			Name:           "requests",
			Version:        "3.5",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 14},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourcefilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 11, End: 14},
				Filename: sourcefilePath,
			},
			IsDirect: true,
		},
	})
}

func TestRequirementsInMatcher_Match_SubstringVersionAmbiguity(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file-substring-version/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	sourceFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// "2.0" is a substring of "12.0"; substring matching would wrongly claim foo@2.0
	packages := []lockfile.PackageDetails{
		{
			Name:           "foo",
			Version:        "2.0",
			PackageManager: models.Requirements,
		},
		{
			Name:           "foo",
			Version:        "12.0",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// foo@2.0 is NOT pinned by "foo==12.0" — must remain unmatched
			Name:           "foo",
			Version:        "2.0",
			PackageManager: models.Requirements,
		},
		{
			// foo@12.0 is the exact pin — gets the location
			Name:           "foo",
			Version:        "12.0",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 10},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 4},
				Filename: sourcefilePath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 6, End: 10},
				Filename: sourcefilePath,
			},
			IsDirect: true,
		},
	})
}

func TestRequirementsInMatcher_Match_RangeConstraintFallback(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file-range-constraints/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	sourceFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Two range constraints for the same package name — fallback must distribute
	// one resolved package per line rather than collapsing both onto line 1.
	packages := []lockfile.PackageDetails{
		{
			Name:           "foo",
			Version:        "1.5",
			PackageManager: models.Requirements,
		},
		{
			Name:           "foo",
			Version:        "2.3",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// foo>=1 on line 1 — first unclaimed package gets this line
			Name:           "foo",
			Version:        "1.5",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 4},
				Filename: sourcefilePath,
			},
			// VersionLocation nil: "1.5" not present in "foo>=1"
			IsDirect: true,
		},
		{
			// foo>=2 on line 2 — second unclaimed package gets this line
			Name:           "foo",
			Version:        "2.3",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 4},
				Filename: sourcefilePath,
			},
			// VersionLocation nil: "2.3" not present in "foo>=2"
			IsDirect: true,
		},
	})
}

func TestRequirementsInMatcher_Match_DirectURLReference(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file-url/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	sourceFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "pyroxy",
			Version:        "",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// pyroxy @ git+https://... in .in (line 1) → URL direct reference must not be skipped
			Name:           "pyroxy",
			Version:        "",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 52},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourcefilePath,
			},
			// VersionLocation is nil: empty version string
			IsDirect: true,
		},
	})
}

func TestRequirementsInMatcher_Match_EnvironmentMarkerOnly(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pip/with-in-file-markers/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"requirements.in"))

	sourceFile, err := lockfile.OpenLocalDepFile(basePath + "requirements.in")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []lockfile.PackageDetails{
		{
			Name:           "aa",
			Version:        "1.0",
			PackageManager: models.Requirements,
		},
	}
	err = requirementsInMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			// aa; python_version=='2.7' in .in (line 1) → semicolon must not be included in name
			Name:           "aa",
			Version:        "1.0",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 26},
				Filename: sourcefilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 1, End: 1},
				Column:   models.Position{Start: 1, End: 3},
				Filename: sourcefilePath,
			},
			// VersionLocation is nil: "1.0" not present in the .in line
			IsDirect: true,
		},
	})
}
