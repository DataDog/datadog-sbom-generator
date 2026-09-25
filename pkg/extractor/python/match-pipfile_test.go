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

var pipfileMatcher = python.PipfileMatcher{}

func TestPipfileMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/pipfile/does-not-exist/Pipfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pipfileMatcher.GetSourceFile(lockFile)
	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestPipfileMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/pipfile/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"Pipfile"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "Pipfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := pipfileMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestPipfileMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pipfile/one-package/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "markupsafe",
			PackageManager: models.Requirements,
		},
	}
	err = pipfileMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "markupsafe",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 17},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 15, End: 16},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestPipfileMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pipfile/transitive/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "asgiref",
			PackageManager: models.Requirements,
		},
		{
			Name:           "django",
			PackageManager: models.Requirements,
		},
		{
			Name:           "ply",
			PackageManager: models.Requirements,
		},
		{
			Name:           "sqlparse",
			PackageManager: models.Requirements,
		},
		{
			Name:           "typing-extensions",
			PackageManager: models.Requirements,
		},
	}
	err = pipfileMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "asgiref",
			PackageManager: models.Requirements,
		},
		{
			Name:           "django",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 7},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 11, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "ply",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 13},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 1, End: 4},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 8, End: 12},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "sqlparse",
			PackageManager: models.Requirements,
		},
		{
			Name:           "typing-extensions",
			PackageManager: models.Requirements,
		},
	})
}

// TestPipfileMatcher_Match_DoesNotMatchSubstringOfAnotherPackageName is a regression test for a
// bug where a package name that is a substring of another declared package name (e.g.
// "requests" inside "requests-oauthlib") had its correct lockfile location overwritten with the
// manifest location of the unrelated package, and was incorrectly marked as a direct dependency.
func TestPipfileMatcher_Match_DoesNotMatchSubstringOfAnotherPackageName(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pipfile/substring-collision/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	transitiveLockLocation := models.FilePosition{
		Line:     models.Position{Start: 42, End: 42},
		Column:   models.Position{Start: 1, End: 10},
		Filename: "../fixtures/pipfile/substring-collision/Pipfile.lock",
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "requests-oauthlib",
			PackageManager: models.Requirements,
		},
		{
			Name:           "requests",
			PackageManager: models.Requirements,
			LocationRole:   models.LocationRoleLockfile,
			BlockLocation:  transitiveLockLocation,
		},
	}
	err = pipfileMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "requests-oauthlib",
			PackageManager: models.Requirements,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 28},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 1, End: 18},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 22, End: 27},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			// "requests" must keep its original lockfile location untouched: it is not
			// declared in the Pipfile, so it must not match the "requests-oauthlib" line.
			Name:           "requests",
			PackageManager: models.Requirements,
			LocationRole:   models.LocationRoleLockfile,
			BlockLocation:  transitiveLockLocation,
		},
	})
}

// TestPipfileMatcher_Match_PoetryInlineTableWithNestedArray is a regression test for a bug where
// pep621InlineArrayNames matched any "key = ... [ ... ]" line regardless of what came between the
// "=" and the "[", so a Poetry inline-table dependency such as
// `requests = { version = "^2", extras = ["socks"] }` was misparsed as a PEP 621 dependency array,
// extracting "socks" (from the nested "extras" array) instead of "requests". This left "requests"
// unmatched and, if "socks" happened to be an existing package, could scribble a manifest location
// onto it that it does not have.
func TestPipfileMatcher_Match_PoetryInlineTableWithNestedArray(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pipfile/poetry-inline-table-with-array/Pipfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "socks", PackageManager: models.Poetry},
	}
	err = pipfileMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "requests",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 50},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 1, End: 9},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 2, End: 2},
				Column:   models.Position{Start: 25, End: 46},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			// "socks" is nested inside the "extras" array of the inline table, not a
			// top-level dependency declaration, so it must not be matched at all.
			Name:           "socks",
			PackageManager: models.Poetry,
		},
	})
}
