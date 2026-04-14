package php_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/php"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestComposerLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "composer.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/composer.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/composer.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/composer.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.composer.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := php.ComposerLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseComposerLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/empty.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseComposerLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/one-package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "sentry/sdk",
			Version:        "2.0.4",
			PackageManager: models.Composer,
			Commit:         "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem:      models.EcosystemPackagist,
		},
	})
}

func TestParseComposerLock_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/one-package-dev.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "sentry/sdk",
			Version:        "2.0.4",
			PackageManager: models.Composer,
			Commit:         "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem:      models.EcosystemPackagist,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseComposerLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/two-packages.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "sentry/sdk",
			Version:        "2.0.4",
			PackageManager: models.Composer,
			Commit:         "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem:      models.EcosystemPackagist,
		},
		{
			Name:           "theseer/tokenizer",
			Version:        "1.1.3",
			PackageManager: models.Composer,
			Commit:         "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
			Ecosystem:      models.EcosystemPackagist,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseComposerLock_TwoPackagesAlt(t *testing.T) {
	t.Parallel()

	packages, err := php.ParseComposerLock("../fixtures/composer/two-packages-alt.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "sentry/sdk",
			Version:        "2.0.4",
			PackageManager: models.Composer,
			Commit:         "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
			Ecosystem:      models.EcosystemPackagist,
		},
		{
			Name:           "theseer/tokenizer",
			Version:        "1.1.3",
			PackageManager: models.Composer,
			Commit:         "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
			Ecosystem:      models.EcosystemPackagist,
		},
	})
}

func TestParseComposerLock_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs("../fixtures/composer/two-packages.json")
	if err != nil {
		t.Fatalf("could not get absolute path: %v", err)
	}

	packages, err := php.ParseComposerLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// two-packages.json has:
	// "packages" array with sentry/sdk at lines 9-39
	// "packages-dev" array with theseer/tokenizer at lines 42-77
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

	// sentry/sdk starts at line 9 (opening {) and ends at line 39 (closing })
	assert.Equal(t, 9, pkgMap["sentry/sdk"].BlockLocation.Line.Start)
	assert.Equal(t, 39, pkgMap["sentry/sdk"].BlockLocation.Line.End)

	// theseer/tokenizer starts at line 42 and ends at line 77
	assert.Equal(t, 42, pkgMap["theseer/tokenizer"].BlockLocation.Line.Start)
	assert.Equal(t, 77, pkgMap["theseer/tokenizer"].BlockLocation.Line.End)

	// Verify path is absolute
	assert.True(t, filepath.IsAbs(path), "path should be absolute")
}
