package python_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseUvLock_SinglePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/uv/single-package.lock"))
	packages, err := python.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
		},
		{
			Name:           "certifi",
			Version:        "2025.4.26",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "charset-normalizer",
			Version:        "3.4.2",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "idna",
			Version:        "3.10",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "urllib3",
			Version:        "2.4.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
	})
}

func TestParseUvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := python.ParseUvLock("../fixtures/uv/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseUvLock_MultiplePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/uv/multiple-packages.lock"))
	packages, err := python.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "bottle",
			Version:        "0.13.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
		},
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
		},
		{
			Name:           "certifi",
			Version:        "2025.4.26",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "charset-normalizer",
			Version:        "3.4.2",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "idna",
			Version:        "3.10",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "urllib3",
			Version:        "2.4.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
	})
}

func TestParseUvLock_DevPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/uv/dev-package.lock"))
	packages, err := python.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
		},
		{
			Name:           "bottle",
			Version:        "0.13.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
		},
		{
			Name:           "pytest",
			Version:        "8.3.5",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "certifi",
			Version:        "2025.4.26",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "charset-normalizer",
			Version:        "3.4.2",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "idna",
			Version:        "3.10",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "urllib3",
			Version:        "2.4.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "colorama",
			Version:        "0.4.6",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "iniconfig",
			Version:        "2.1.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "packaging",
			Version:        "25.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
		{
			Name:           "pluggy",
			Version:        "1.6.0",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       false,
		},
	})
}

func TestParseUvLock_SinglePackage_BlockLocation(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs("../fixtures/uv/single-package.lock")
	if err != nil {
		t.Fatalf("could not get absolute path: %v", err)
	}

	packages, err := python.ParseUvLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// single-package.lock has 6 [[package]] sections:
	// line 5: certifi, line 14: charset-normalizer, line 36: idna,
	// line 45: requests, line 60: urllib3, line 69: uv (root, skipped)
	// Root package "uv" is skipped, so 5 packages returned.
	assert.Equal(t, 5, len(packages), "expected 5 packages (root skipped)")

	for _, pkg := range packages {
		assert.NotEqual(t, 0, pkg.BlockLocation.Line.Start,
			"expected BlockLocation.Line.Start to be set for package %s", pkg.Name)
		assert.NotEmpty(t, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to be set for package %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to match the lockfile path for package %s", pkg.Name)
	}

	// Verify specific positions
	pkgMap := make(map[string]lockfile.PackageDetails)
	for _, pkg := range packages {
		pkgMap[pkg.Name] = pkg
	}

	// certifi starts at line 5
	assert.Equal(t, 5, pkgMap["certifi"].BlockLocation.Line.Start)

	// idna starts at line 36
	assert.Equal(t, 36, pkgMap["idna"].BlockLocation.Line.Start)

	// requests starts at line 45
	assert.Equal(t, 45, pkgMap["requests"].BlockLocation.Line.Start)

	// Verify path is absolute
	assert.True(t, filepath.IsAbs(path), "path should be absolute")
}
