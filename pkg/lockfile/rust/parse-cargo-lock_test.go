package rust_test

import (
	"io/fs"
	"testing"

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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wasi",
			Version:        "0.10.2+wasi-snapshot-preview1",
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}
