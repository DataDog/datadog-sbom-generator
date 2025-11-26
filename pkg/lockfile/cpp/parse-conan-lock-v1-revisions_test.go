package cpp_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/cpp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseConanLock_v1_revisions_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_revisions_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_revisions_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/empty.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseConanLock_v1_revisions_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_revisions_NoName(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/no-name.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "zlib",
			Version:        "1.2.11",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}

func TestParseConanLock_v1_revisions_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/two-packages.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

func TestParseConanLock_v1_revisions_NestedDependencies(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/nested-dependencies.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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

func TestParseConanLock_v1_revisions_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := cpp.ParseConanLock("../fixtures/conan/one-package-dev.v1.revisions.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "ninja",
			Version:        "1.11.1",
			PackageManager: models.Conan,
			Ecosystem:      models.EcosystemConanCenter,
		},
	})
}
