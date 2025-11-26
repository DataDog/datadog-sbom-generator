package lockfile_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseOSVScannerResults_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_InvalidJSON(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/empty.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseOSVScannerResults_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/one-package.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "activesupport",
			Version:        "7.0.7",
			PackageManager: models.Unknown,
			Ecosystem:      models.EcosystemRubyGems,
		},
	})
}

func TestParseOSVScannerResults_OnePackageCommit(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/one-package-commit.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Commit:         "9a6bd55c9d0722cb101fe85a3b22d89e4ff4fe52",
			PackageManager: models.Unknown,
		},
	})
}

func TestParseOSVScannerResults_MultiPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseOSVScannerResults("fixtures/osvscannerresults/multi-packages-with-vulns.json")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "crossbeam-utils",
			Version:        "0.6.6",
			PackageManager: models.Unknown,
			Ecosystem:      models.EcosystemCratesIO,
		},
		{
			Name:           "memoffset",
			Version:        "0.5.6",
			PackageManager: models.Unknown,
			Ecosystem:      models.EcosystemCratesIO,
		},
		{
			Name:           "smallvec",
			Version:        "1.6.0",
			PackageManager: models.Unknown,
			Ecosystem:      models.EcosystemCratesIO,
		},
	})
}
