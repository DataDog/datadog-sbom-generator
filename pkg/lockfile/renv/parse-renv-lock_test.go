package renv_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/renv"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestParseRenvLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseRenvLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "morning",
			Version:        "0.1.0",
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		},
	})
}

func TestParseRenvLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markdown",
			Version:        "1.0",
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		},
		{
			Name:           "mime",
			Version:        "0.7",
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		},
	})
}

func TestParseRenvLock_WithMixedSources(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/with-mixed-sources.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "markdown",
			Version:        "1.0",
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		},
	})
}

func TestParseRenvLock_WithBioconductor(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/with-bioconductor.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// currently Bioconductor is not supported
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "BH",
			Version:        "1.75.0-0",
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		},
	})
}

func TestParseRenvLock_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packagesByName := make(map[string]lockfile.PackageDetails)
	for _, pkg := range packages {
		packagesByName[pkg.Name] = pkg
	}

	// markdown block: lines 12-18 in "Packages" section
	markdown := packagesByName["markdown"]
	assert.Equal(t, 12, markdown.BlockLocation.Line.Start)
	assert.Equal(t, 18, markdown.BlockLocation.Line.End)
	assert.Equal(t, 5, markdown.BlockLocation.Column.Start)
	assert.Equal(t, 6, markdown.BlockLocation.Column.End)
	assert.Contains(t, markdown.BlockLocation.Filename, "two-packages.lock")

	// mime block: lines 19-25 in "Packages" section
	mime := packagesByName["mime"]
	assert.Equal(t, 19, mime.BlockLocation.Line.Start)
	assert.Equal(t, 25, mime.BlockLocation.Line.End)
	assert.Equal(t, 5, mime.BlockLocation.Column.Start)
	assert.Equal(t, 6, mime.BlockLocation.Column.End)
	assert.Contains(t, mime.BlockLocation.Filename, "two-packages.lock")
}

func TestParseRenvLock_WithoutRepository(t *testing.T) {
	t.Parallel()

	packages, err := renv.ParseRenvLock("../fixtures/renv/without-repository.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}
