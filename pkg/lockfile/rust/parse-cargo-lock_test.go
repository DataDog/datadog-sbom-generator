package rust_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/rust"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestCargoLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "Cargo.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/Cargo.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.Cargo.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := rust.CargoLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCargoLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/not-toml.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseCargoLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/one-package.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "addr2line",
			Version:        "0.15.2",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}

func TestParseCargoLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/two-packages.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "addr2line",
			Version:        "0.15.2",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
		{
			Name:           "syn",
			Version:        "1.0.73",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}

func TestParseCargoLock_TwoPackagesWithLocal(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/two-packages-with-local.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "addr2line",
			Version:        "0.15.2",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
		{
			Name:           "local-rust-pkg",
			Version:        "0.1.0",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}

func TestParseCargoLock_PackageWithBuildString(t *testing.T) {
	t.Parallel()

	packages, err := rust.ParseCargoLock("../fixtures/cargo/package-with-build-string.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wasi",
			Version:        "0.10.2+wasi-snapshot-preview1",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}

func TestParseCargoLock_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs("../fixtures/cargo/two-packages.lock")
	if err != nil {
		t.Fatalf("could not get absolute path: %v", err)
	}

	packages, err := rust.ParseCargoLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// two-packages.lock has:
	// line 5: "[[package]]"  (addr2line block, lines 5-12)
	// line 14: "[[package]]" (syn block, lines 14-23)
	assert.Equal(t, 2, len(packages), "expected 2 packages")

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

	// addr2line starts at line 5 ("[[package]]"), ends before the blank line at line 13
	assert.Equal(t, 5, pkgMap["addr2line"].BlockLocation.Line.Start)
	assert.Equal(t, 12, pkgMap["addr2line"].BlockLocation.Line.End)

	// syn starts at line 14 ("[[package]]"), ends at line 24 (last package includes trailing content)
	assert.Equal(t, 14, pkgMap["syn"].BlockLocation.Line.Start)
	assert.Equal(t, 24, pkgMap["syn"].BlockLocation.Line.End)

	// Verify path is absolute
	assert.True(t, os.IsPathSeparator(path[0]) || filepath.IsAbs(path),
		"path should be absolute")
}
