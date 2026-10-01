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

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInlineWithComma is a regression test for a
// bug where the inline PEP 621 array parser split its contents on every comma, which breaks a PEP
// 508 requirement whose version constraint itself contains a comma, e.g. `"urllib3>=1.26,<3"`. The
// naive split produced two malformed fragments (`"urllib3>=1.26` and `<3"`), neither of which parsed
// as a valid quoted item, so the package silently failed to match at all.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInlineWithComma(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-inline-array-with-comma/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "urllib3", PackageManager: models.Poetry},
		{Name: "requests", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "urllib3",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 48},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 18, End: 25},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
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
				Column:   models.Position{Start: 38, End: 46},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayWithComment is a regression test for a bug
// where a trailing TOML comment on a multiline PEP 621 array item, e.g.
// `"requests>=2",  # needed by API`, made pep621ArrayItemName reject the line: it required nothing
// to follow the closing quote besides an optional comma, so the trailing comment left the
// dependency unmatched (no manifest location, IsDirect=false).
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayWithComment(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array-with-comment/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "flask", PackageManager: models.Poetry},
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
				Column:   models.Position{Start: 5, End: 36},
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
				Column:   models.Position{Start: 5, End: 13},
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
	})
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInlineSharedPrefix is a regression test for a
// bug where the NameLocation of a package declared in an inline PEP 621 array was computed by
// searching the package name as a substring of the whole line. For
// `dependencies = ["requests-oauthlib", "requests"]`, searching for "requests" found the occurrence
// inside "requests-oauthlib" instead of the package's own entry, pointing callers at the wrong
// token.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayInlineSharedPrefix(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-inline-array-shared-prefix/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests-oauthlib", PackageManager: models.Poetry},
		{Name: "requests", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "requests-oauthlib",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 49},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 18, End: 35},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "requests",
			PackageManager: models.Poetry,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 1, End: 49},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 39, End: 47},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayEscapedQuote is a regression test for a bug
// where a PEP 621 requirement using a TOML double-quoted string with an escaped inner quote, e.g.
// `"requests; python_version < \"3.12\""`, made pep621ArrayItemName find the escaped quote as the
// string terminator (via a plain strings.IndexByte search that does not understand TOML escapes),
// leaving trailing content that caused the whole item to be rejected as unrecognized.
// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayPartialMultiline is a regression test for a
// bug where a PEP 621 dependency array that placed an item on the same physical line as the
// opening or closing bracket, e.g. `dependencies = ["requests>=2",` followed by `"flask"]`, was
// never matched: the opening line fell back to the key "dependencies" and the closing line was
// rejected as an unrecognized standalone item, since neither is a single fully-quoted token nor a
// same-line inline array.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayPartialMultiline(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array-partial-multiline/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "flask", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	for _, pkg := range packages {
		assert.True(t, pkg.IsDirect, "expected %s to be recognized as a direct dependency", pkg.Name)
		assert.Equal(t, models.LocationRoleManifest, pkg.LocationRole, "expected %s to have a manifest location", pkg.Name)
	}
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayLeadingWhitespace is a regression test for
// a bug where a PEP 508 requirement with leading whitespace inside the quotes, e.g.
// `" requests >=2"`, made pep621ArrayItemName scan the name from the untrimmed spec: IndexFunc
// stopped at the leading space immediately, producing an empty name and rejecting the entry.
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayLeadingWhitespace(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array-leading-whitespace/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "flask", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	for _, pkg := range packages {
		assert.True(t, pkg.IsDirect, "expected %s to be recognized as a direct dependency", pkg.Name)
		assert.Equal(t, models.LocationRoleManifest, pkg.LocationRole, "expected %s to have a manifest location", pkg.Name)
	}
}

// TestPyprojectTomlMatcher_Match_PEP621DependencyArrayNameNormalization is a regression test for
// a bug where the manifest key comparison used a plain case-insensitive match instead of PEP 503
// name normalization, so a manifest entry spelled "my_package" never matched a lockfile package
// recorded under its canonical name "my-package".
func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayNameNormalization(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array-name-normalization/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "my-package", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.True(t, packages[0].IsDirect, "expected my-package to be recognized as a direct dependency")
	assert.Equal(t, models.LocationRoleManifest, packages[0].LocationRole)
}

func TestPyprojectTomlMatcher_Match_PEP621DependencyArrayEscapedQuote(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/pep621-array-escaped-quote/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "flask", PackageManager: models.Poetry},
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
				Column:   models.Position{Start: 5, End: 43},
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
				Column:   models.Position{Start: 5, End: 13},
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
	})
}

// TestPyprojectTomlMatcher_Match_PoetryNestedDependencyTable is a regression test for a bug where a
// Poetry dependency expanded into its own nested table (e.g. [tool.poetry.dependencies.requests]
// followed by `version = "^2"`) was never matched, because the dependency name only appears in the
// table header itself and the line-by-line scanner only looked for "key = value" assignments.
func TestPyprojectTomlMatcher_Match_PoetryNestedDependencyTable(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/poetry-nested-dependency-table/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.True(t, packages[0].IsDirect, "expected requests to be recognized as a direct dependency")
	assert.Equal(t, models.LocationRoleManifest, packages[0].LocationRole)
	assert.Equal(t, 4, packages[0].BlockLocation.Line.Start, "expected requests manifest location on the [tool.poetry.dependencies.requests] header line")
}

// TestPyprojectTomlMatcher_Match_ScriptsTableNotMatched is a regression test ensuring that a table
// unrelated to dependency declarations, such as [tool.poetry.scripts], is never scanned for package
// names. Without this restriction, a script entry that happens to share its name with a real
// dependency (e.g. a "flask" console-script entry point) could be mistaken for a manifest
// declaration of the "flask" package.
func TestPyprojectTomlMatcher_Match_ScriptsTableNotMatched(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/scripts-table-not-matched/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "flask", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.True(t, packages[0].IsDirect, "expected requests to be recognized as a direct dependency")
	assert.False(t, packages[1].IsDirect, "expected flask to NOT be recognized as a direct dependency from the scripts table")
	assert.NotEqual(t, models.LocationRoleManifest, packages[1].LocationRole)
}

// TestPyprojectTomlMatcher_Match_DependencyGroups is a regression test ensuring that packages
// declared under [dependency-groups] (PEP 735, used by uv) still get manifest-level enrichment.
// isDependencyTable previously only allowed a fixed set of tables, omitting [dependency-groups],
// so a uv project's dev-only dependencies fell back to their raw uv.lock location with no
// manifest occurrence and IsDirect left unset.
func TestPyprojectTomlMatcher_Match_DependencyGroups(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/dependency-groups/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Uv},
		{Name: "pytest", PackageManager: models.Uv},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.True(t, packages[0].IsDirect, "expected requests to be recognized as a direct dependency")
	assert.Equal(t, models.LocationRoleManifest, packages[0].LocationRole)

	assert.True(t, packages[1].IsDirect, "expected pytest under [dependency-groups] to be recognized as a direct dependency")
	assert.Equal(t, models.LocationRoleManifest, packages[1].LocationRole, "expected pytest to get its manifest location from [dependency-groups]")
}

// TestPyprojectTomlMatcher_Match_DependencyGroupInclusionOnly is a regression test for a bug where
// the Poetry multi-constraint-array fallback (which treats an array's own assignment key as a
// manifest key when the array has no quoted string item) also fired for [dependency-groups]. A
// PEP 735 group that only includes another group, e.g. `dev = [{include-group = "test"}]`, has no
// string item either, so the fallback incorrectly treated the group name ("dev", "empty",
// "inline") as a package name, both for a multiline array and for one declared inline on a single
// line (e.g. `inline = [{include-group = "test"}]` or `empty = []`). If the lockfile happens to
// contain an unrelated transitive package sharing one of those names, it was wrongly marked
// IsDirect with this group's manifest location.
func TestPyprojectTomlMatcher_Match_DependencyGroupInclusionOnly(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/dependency-groups-inclusion-only/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "pytest", PackageManager: models.Uv},
		{Name: "dev", PackageManager: models.Uv},
		{Name: "empty", PackageManager: models.Uv},
		{Name: "inline", PackageManager: models.Uv},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.True(t, packages[0].IsDirect, "expected pytest under [dependency-groups] to be recognized as a direct dependency")
	assert.Equal(t, models.LocationRoleManifest, packages[0].LocationRole)

	for _, pkg := range packages[1:] {
		assert.False(t, pkg.IsDirect, "expected the unrelated '%s' package to NOT be marked direct from an inclusion-only/empty group", pkg.Name)
		assert.NotEqual(t, models.LocationRoleManifest, pkg.LocationRole, "expected '%s' to NOT get a manifest location from an inclusion-only/empty group", pkg.Name)
	}
}

// TestPyprojectTomlMatcher_Match_TableHeaderWithTrailingComment is a regression test for a bug
// where isTable did not strip a trailing TOML comment before checking whether a line closes with
// "]", so a valid header such as `[project] # metadata` was not recognized as a table header at
// all. This left the matcher either skipping every dependency in the first table of the file, or
// leaking the previous table's state into the next section.
func TestPyprojectTomlMatcher_Match_TableHeaderWithTrailingComment(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/pyproject-toml/table-header-with-comment/pyproject.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{Name: "requests", PackageManager: models.Poetry},
		{Name: "pytest", PackageManager: models.Poetry},
	}
	err = pyprojectTOMLMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	for _, pkg := range packages {
		assert.True(t, pkg.IsDirect, "expected %s to be recognized as a direct dependency", pkg.Name)
		assert.Equal(t, models.LocationRoleManifest, pkg.LocationRole, "expected %s to have a manifest location", pkg.Name)
	}
}
