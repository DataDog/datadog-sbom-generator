package python_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestPdmExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty",
			path: "",
			want: false,
		},
		{
			name: "plain",
			path: "pdm.lock",
			want: true,
		},
		{
			name: "absolute",
			path: "/path/to/pdm.lock",
			want: true,
		},
		{
			name: "relative",
			path: "../../pdm.lock",
			want: true,
		},
		{
			name: "in-path",
			path: "/path/with/pdm.lock/in/middle",
			want: false,
		},
		{
			name: "invalid-suffix",
			path: "pdm.lock.file",
			want: false,
		},
		{
			name: "invalid-prefix",
			path: "project.name.pdm.lock",
			want: false,
		},
	}

	for _, test := range tests {
		tst := test
		t.Run(tst.name, func(t *testing.T) {
			t.Parallel()
			ext := python.PdmLockExtractor{}
			should := ext.ShouldExtract(tst.path)
			if should != tst.want {
				t.Errorf("ShouldExtract() - got %v, expected %v", should, tst.want)
			}
		})
	}
}

func expectNilErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}
}

func TestParsePdmLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParsePdmLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/not-toml.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParsePdmLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/empty.toml")

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParsePdmLock_SinglePackage(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/single-package.toml")

	expectNilErr(t, err)
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		},
	})
}

func TestParsePdmLock_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/two-packages.toml")

	expectNilErr(t, err)
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		},
		{
			Name:           "six",
			Version:        "1.16.0",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		},
	})
}

func TestParsePdmLock_PackageWithDevDependencies(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/dev-dependency.toml")

	expectNilErr(t, err)
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		},
		{
			Name:           "pyroute2",
			Version:        "0.7.11",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "win-inet-pton",
			Version:        "1.1.0",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParsePdmLock_PackageWithOptionalDependency(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/optional-dependency.toml")

	expectNilErr(t, err)
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		},
		{
			Name:           "pyroute2",
			Version:        "0.7.11",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			DepGroups:      []string{"optional"},
		},
		{
			Name:           "win-inet-pton",
			Version:        "1.1.0",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			DepGroups:      []string{"optional"},
		},
	})
}

func TestParsePdmLock_PackageWithGitDependency(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/git-dependency.toml")

	expectNilErr(t, err)
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			Commit:         "65bab7582ce14c55cdeec2244c65ea23039c9e6f",
		},
	})
}

func TestParsePdmLock_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs("../fixtures/pdm/two-packages.toml")
	if err != nil {
		t.Fatalf("could not get absolute path: %v", err)
	}

	packages, err := python.ParsePdmLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// two-packages.toml has:
	// line 4: [metadata]
	// line 10: [[package]] (six, lines 10-19)
	// line 21: [[package]] (toml, lines 21-30)
	assert.Len(t, packages, 2, "expected 2 packages")

	for _, pkg := range packages {
		assert.NotEqual(t, 0, pkg.BlockLocation.Line.Start,
			"expected BlockLocation.Line.Start to be set for package %s", pkg.Name)
		assert.NotEmpty(t, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to be set for package %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to match the lockfile path for package %s", pkg.Name)
	}

	// Verify specific positions
	pkgMap := make(map[string]extractor.PackageDetails)
	for _, pkg := range packages {
		pkgMap[pkg.Name] = pkg
	}

	// six starts at line 10 ("[[package]]")
	assert.Equal(t, 10, pkgMap["six"].BlockLocation.Line.Start)

	// toml starts at line 21 ("[[package]]")
	assert.Equal(t, 21, pkgMap["toml"].BlockLocation.Line.Start)

	// Verify path is absolute
	assert.True(t, filepath.IsAbs(path), "path should be absolute")
}
