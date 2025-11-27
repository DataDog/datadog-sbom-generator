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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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
