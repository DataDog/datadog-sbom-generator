package lockfile_test

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
)

func TestParseUvLock_SinglePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/uv/single-package.lock"))
	packages, err := lockfile.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			Dependencies: []*lockfile.PackageDetails{
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
			},
		},
	})
}

func TestParseUvLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseUvLock("fixtures/uv/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseUvLock_MultiplePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/uv/multiple-packages.lock"))
	packages, err := lockfile.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			Dependencies: []*lockfile.PackageDetails{
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
			},
		},
		{
			Name:           "bottle",
			Version:        "0.13.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			Dependencies:   nil,
		},
	})
}

func TestParseUvLock_DevPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/uv/dev-package.lock"))
	packages, err := lockfile.ParseUvLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "requests",
			Version:        "2.32.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			Dependencies: []*lockfile.PackageDetails{
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
			},
		},
		{
			Name:           "bottle",
			Version:        "0.13.3",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			Dependencies:   nil,
		},
		{
			Name:           "pytest",
			Version:        "8.3.5",
			PackageManager: models.Uv,
			Ecosystem:      models.EcosystemPyPI,
			IsDirect:       true,
			DepGroups:      []string{"dev"},
			Dependencies: []*lockfile.PackageDetails{
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
			},
		},
	})
}

//
//func TestParseUvLock_DevPackage(t *testing.T) {
//	t.Parallel()
//	dir, err := os.Getwd()
//	if err != nil {
//		t.Errorf("Got unexpected error: %v", err)
//	}
//
//	path := filepath.FromSlash(filepath.Join(dir, "fixtures/uv/dev-package.lock"))
//	packages, err := lockfile.ParseUvLock(path)
//	if err != nil {
//		t.Errorf("Got unexpected error: %v", err)
//	}
//
//	expectPackages(t, packages, []lockfile.PackageDetails{
//		{
//			Name:           "requests",
//			Version:        "2.32.3",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       true,
//		},
//		{
//			Name:           "bottle",
//			Version:        "0.13.3",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       true,
//		},
//		{
//			Name:           "certifi",
//			Version:        "2025.4.26",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       false,
//		},
//		{
//			Name:           "charset-normalizer",
//			Version:        "3.4.2",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       false,
//		},
//		{
//			Name:           "idna",
//			Version:        "3.10",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       false,
//		},
//		{
//			Name:           "urllib3",
//			Version:        "2.4.0",
//			PackageManager: models.Uv,
//			Ecosystem:      models.EcosystemPyPI,
//			IsDirect:       false,
//		},
//	})
//}
