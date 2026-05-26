package rust_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/rust"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
)

var cargoTomlMatcher = rust.CargoTomlMatcher{}

func TestCargoTomlMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/no-toml/Cargo.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := cargoTomlMatcher.GetSourceFile(lockFile)
	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestCargoTomlMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/cargo/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"Cargo.toml"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "Cargo.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := cargoTomlMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestCargoTomlMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/one-package/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 10, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestCargoTomlMatcher_Match_SubstringNotMatched(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/substring-match/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
		},
		{
			Name:           "serde_json",
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// serde should match on line 9, NOT serde_json on line 10
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 10, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "serde_json",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 21},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 11},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 15, End: 20},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestCargoTomlMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/transitive/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
		},
		{
			Name:           "syn", // Transitive, not in Cargo.toml
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Only serde should be matched, syn remains unmatched (transitive)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 10, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "syn",
			PackageManager: models.Crates,
			// No BlockLocation, NameLocation, or VersionLocation
			// IsDirect remains false (default)
		},
	})
}

func TestCargoTomlMatcher_Match_DevDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/dev-deps/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "criterion",
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "criterion",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 20},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 14, End: 19},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
	})
}

func TestCargoTomlMatcher_Match_BuildDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/build-deps/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "cc",
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "cc",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 13},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 3},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 7, End: 12},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"build"},
		},
	})
}

func TestCargoTomlMatcher_Match_AllSections(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/all-sections/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
		},
		{
			Name:           "tokio",
			PackageManager: models.Crates,
		},
		{
			Name:           "criterion",
			PackageManager: models.Crates,
		},
		{
			Name:           "cc",
			PackageManager: models.Crates,
		},
		{
			Name:           "syn", // Transitive, not in Cargo.toml
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 16},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 10, End: 15},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "tokio",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 17},
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
				Column:   models.Position{Start: 10, End: 16},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "criterion",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 20},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 14, End: 19},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
		{
			Name:           "cc",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 1, End: 13},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 1, End: 3},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 7, End: 12},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"build"},
		},
		{
			Name:           "syn",
			PackageManager: models.Crates,
			// No BlockLocation, NameLocation, or VersionLocation
			// IsDirect remains false (default)
		},
	})
}

func TestCargoTomlMatcher_Match_MultipleVersions(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/multi-version/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			Version:        "0.9.15",
			PackageManager: models.Crates,
		},
		{
			Name:           "serde",
			Version:        "1.0.214",
			PackageManager: models.Crates,
		},
	}
	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// serde 1.0.214 should match [dependencies] serde = "1.0" on line 9
	// serde 0.9.15 should match [dev-dependencies] serde = "0.9" on line 12
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			Version:        "0.9.15",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 14},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 10, End: 13},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
		{
			Name:           "serde",
			Version:        "1.0.214",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 14},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 10, End: 13},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
	})
}

func TestCargoTomlMatcher_Match_TableForm(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/cargo/table-form/Cargo.toml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "serde",
			Version:        "1.0.214",
			PackageManager: models.Crates,
		},
		{
			Name:           "tokio",
			Version:        "1.0.0",
			PackageManager: models.Crates,
		},
		{
			Name:           "criterion",
			Version:        "0.5.1",
			PackageManager: models.Crates,
		},
	}

	err = cargoTomlMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "serde",
			Version:        "1.0.214",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 51},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 1, End: 6},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 22, End: 25},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "tokio",
			Version:        "1.0.0",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 1, End: 49},
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
				Column:   models.Position{Start: 22, End: 25},
				Filename: sourceFile.Path(),
			},
			IsDirect: true,
		},
		{
			Name:           "criterion",
			Version:        "0.5.1",
			PackageManager: models.Crates,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 58},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 1, End: 10},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 26, End: 29},
				Filename: sourceFile.Path(),
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
		},
	})
}
