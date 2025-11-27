package python_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/not-toml.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/empty.toml")

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePdmLock_SinglePackage(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePdmLock("../fixtures/pdm/single-package.toml")

	expectNilErr(t, err)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
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
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "toml",
			Version:        "0.10.2",
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
			Commit:         "65bab7582ce14c55cdeec2244c65ea23039c9e6f",
		},
	})
}
