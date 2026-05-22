package cpp_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/cpp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseConanLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/empty.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_NoName(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/no-name.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/two-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
		{
			Name:           "bzip2",
			Version:        "1.0.8",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/nested-dependencies.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.13",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
		{
			Name:           "bzip2",
			Version:        "1.0.8",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
		{
			Name:           "freetype",
			Version:        "2.12.1",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
		{
			Name:           "libpng",
			Version:        "1.6.39",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
		{
			Name:           "brotli",
			Version:        "1.0.9",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package-dev.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "ninja",
			Version:        "1.11.1",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_OldFormat00(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/old-format-0.0.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_OldFormat01(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/old-format-0.1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_OldFormat02(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/old-format-0.2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_OldFormat03(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/old-format-0.3.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/two-packages.v1.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packagesByName := make(map[string]lockfile.PackageDetails)
	for _, pkg := range packages {
		packagesByName[pkg.Name] = pkg
	}

	absoluteLockfilePath, err := filepath.Abs("../fixtures/conan/two-packages.v1.json")
	if err != nil {
		t.Fatalf("Could not get absolute path: %v", err)
	}

	// Node "1": zlib, lines 14-20, column 7-8
	zlibPkg := packagesByName["zlib"]
	assert.Equal(t, absoluteLockfilePath, zlibPkg.BlockLocation.Filename)
	assert.Equal(t, 14, zlibPkg.BlockLocation.Line.Start)
	assert.Equal(t, 20, zlibPkg.BlockLocation.Line.End)
	assert.Equal(t, 7, zlibPkg.BlockLocation.Column.Start)
	assert.Equal(t, 8, zlibPkg.BlockLocation.Column.End)

	// Node "2": bzip2, lines 21-27, column 7-8
	bzip2Pkg := packagesByName["bzip2"]
	assert.Equal(t, absoluteLockfilePath, bzip2Pkg.BlockLocation.Filename)
	assert.Equal(t, 21, bzip2Pkg.BlockLocation.Line.Start)
	assert.Equal(t, 27, bzip2Pkg.BlockLocation.Line.End)
	assert.Equal(t, 7, bzip2Pkg.BlockLocation.Column.Start)
	assert.Equal(t, 8, bzip2Pkg.BlockLocation.Column.End)
}
