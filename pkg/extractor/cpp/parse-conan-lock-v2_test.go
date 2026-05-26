package cpp_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/cpp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseConanLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseConanLock_v2_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseConanLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/empty.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseConanLock_v2_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
	})
}

func TestParseConanLock_v2_NoName(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/no-name.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
	})
}

func TestParseConanLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/two-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
		{
			Name:           "bzip2",
			Version:        "1.0.8",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
	})
}

func TestParseConanLock_v2_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/nested-dependencies.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.13",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
		{
			Name:           "bzip2",
			Version:        "1.0.8",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
		{
			Name:           "freetype",
			Version:        "2.12.1",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
		{
			Name:           "libpng",
			Version:        "1.6.39",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
		{
			Name:           "brotli",
			Version:        "1.0.9",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"requires"},
		},
	})
}

func TestParseConanLock_v2_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package-dev.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "ninja",
			Version:        "1.11.1",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
			DepGroups:      []string{"build-requires"},
		},
	})
}

func TestParseConanLock_v2_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/two-packages.v2.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packagesByName := make(map[string]extractor.PackageDetails)
	for _, pkg := range packages {
		packagesByName[pkg.Name] = pkg
	}

	absoluteLockfilePath, err := filepath.Abs("../fixtures/conan/two-packages.v2.json")
	if err != nil {
		t.Fatalf("Could not get absolute path: %v", err)
	}

	// zlib on line 4: "zlib/1.2.11#ffa77daf83a57094149707928bdce823%1667396813.184"
	zlibPkg := packagesByName["zlib"]
	assert.Equal(t, absoluteLockfilePath, zlibPkg.BlockLocation.Filename)
	assert.Equal(t, 4, zlibPkg.BlockLocation.Line.Start)
	assert.Equal(t, 4, zlibPkg.BlockLocation.Line.End)

	// bzip2 on line 5: "bzip2/1.0.8#464be69744fa6d48ed01928cfe470008%1666580345.213"
	bzip2Pkg := packagesByName["bzip2"]
	assert.Equal(t, absoluteLockfilePath, bzip2Pkg.BlockLocation.Filename)
	assert.Equal(t, 5, bzip2Pkg.BlockLocation.Line.Start)
	assert.Equal(t, 5, bzip2Pkg.BlockLocation.Line.End)
}
