package system_test

import (
	"io/fs"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/system"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParseDpkgStatus_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseDpkgStatus_Empty(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/empty_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseDpkgStatus_NotAStatus(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/not_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseDpkgStatus_Malformed(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/malformed_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "bash",
			Version:        "",
			Ecosystem:      models.EcosystemDebian,
			PackageManager: models.Unknown,
		},
		{
			Name:           "util-linux",
			Version:        "2.36.1-8+deb11u1",
			Ecosystem:      models.EcosystemDebian,
			PackageManager: models.Unknown,
		},
	})
}

func TestParseDpkgStatus_Single(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/single_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "sudo",
			Version:        "1.8.27-1+deb10u1",
			Ecosystem:      models.EcosystemDebian,
			PackageManager: models.Unknown,
		},
	})
}

func TestParseDpkgStatus_Shuffled(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/shuffled_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "glibc",
			Version:        "2.31-13+deb11u5",
			Ecosystem:      models.EcosystemDebian,
			PackageManager: models.Unknown,
		},
	})
}

func TestParseDpkgStatus_Multiple(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/multiple_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "bash",
			Version:        "5.1-2+deb11u1",
			Ecosystem:      models.EcosystemDebian + ":12",
			PackageManager: models.Unknown,
		},
		{
			Name:           "util-linux",
			Version:        "2.36.1-8+deb11u1",
			Ecosystem:      models.EcosystemDebian + ":12",
			PackageManager: models.Unknown,
		},
		{
			Name:           "glibc",
			Version:        "2.31-13+deb11u5",
			Ecosystem:      models.EcosystemDebian + ":12",
			PackageManager: models.Unknown,
		},
		{
			Name:           "base-files",
			Version:        "12.4+deb12u5",
			Ecosystem:      models.EcosystemDebian + ":12",
			PackageManager: models.Unknown,
		},
	})
}

func TestParseDpkgStatus_Source_Ver_Override(t *testing.T) {
	t.Parallel()

	packages, err := system.ParseDpkgStatus("../fixtures/dpkg/source_ver_override_status")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "lvm2",
			Version:        "2.02.176-4.1ubuntu3",
			Ecosystem:      models.EcosystemDebian,
			PackageManager: models.Unknown,
		},
	})
}
