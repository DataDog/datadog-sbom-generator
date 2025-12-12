package testutil

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/DataDog/datadog-sbom-generator/internal/output"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func ExpectErrContaining(t *testing.T, err error, str string) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !strings.Contains(err.Error(), str) {
		t.Errorf("Expected to get \"%s\" error, but got \"%v\"", str, err)
	}
}

func ExpectErrIs(t *testing.T, err error, expected error) {
	t.Helper()

	if err == nil {
		t.Errorf("Expected to get error, but did not")
	}

	if !errors.Is(err, expected) {
		t.Errorf("Expected to get \"%v\" error but got \"%v\" instead", expected, err)
	}
}

func PackageToString(pkg lockfile.PackageDetails) string {
	commit := pkg.Commit

	if commit == "" {
		commit = "<no commit>"
	}

	groups := strings.Join(pkg.DepGroups, ", ")

	if groups == "" {
		groups = "<no groups>"
	}

	exclusions := strings.Join(pkg.Exclusions, ", ")

	if exclusions == "" {
		exclusions = "<no exclusions>"
	}

	blockLoc := fmt.Sprintf("BlockLocation{Line:%+v Column:%+v Filename:%s}", pkg.BlockLocation.Line, pkg.BlockLocation.Column, pkg.BlockLocation.Filename)

	nameLoc := "<nil>"
	if pkg.NameLocation != nil {
		nameLoc = fmt.Sprintf("{Line:%+v Column:%+v Filename:%s}", pkg.NameLocation.Line, pkg.NameLocation.Column, pkg.NameLocation.Filename)
	}

	versionLoc := "<nil>"
	if pkg.VersionLocation != nil {
		versionLoc = fmt.Sprintf("{Line:%+v Column:%+v Filename:%s}", pkg.VersionLocation.Line, pkg.VersionLocation.Column, pkg.VersionLocation.Filename)
	}

	return fmt.Sprintf("%s@%s (%s, %s, %s, %s, %t, %s) %s NameLocation:%s VersionLocation:%s",
		pkg.Name, pkg.Version, pkg.Ecosystem, commit, groups, pkg.PackageManager, pkg.IsDirect, exclusions,
		blockLoc, nameLoc, versionLoc)
}

func HasPackage(t *testing.T, expectedPkgs []lockfile.PackageDetails, currentPkg lockfile.PackageDetails, ignoreLocations bool) bool {
	t.Helper()

	for _, expectedPkg := range expectedPkgs {
		var ignore []string
		if ignoreLocations {
			ignore = []string{"BlockLocation", "NameLocation", "VersionLocation"}
		}

		if cmp.Equal(expectedPkg, currentPkg, cmpopts.IgnoreFields(lockfile.PackageDetails{}, ignore...)) {
			return true
		}
	}

	return false
}

func InnerExpectPackage(t *testing.T, expectedPkgs []lockfile.PackageDetails, currentPkg lockfile.PackageDetails, ignoreLocations bool) {
	t.Helper()

	if !HasPackage(t, expectedPkgs, currentPkg, ignoreLocations) {
		t.Errorf(
			"Expected packages to include %s@%s (%s), but it did not",
			currentPkg.Name,
			currentPkg.Version,
			currentPkg.Ecosystem,
		)
	}
}

func ExpectPackage(t *testing.T, packages []lockfile.PackageDetails, pkg lockfile.PackageDetails) {
	t.Helper()

	InnerExpectPackage(t, packages, pkg, false)
}

func FindMissingPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails, ignoreLocations bool) []lockfile.PackageDetails {
	t.Helper()
	var missingPackages []lockfile.PackageDetails

	for _, pkg := range actualPackages {
		if !HasPackage(t, expectedPackages, pkg, ignoreLocations) {
			missingPackages = append(missingPackages, pkg)
		}
	}

	return missingPackages
}

func InnerExpectPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails, ignoreLocations bool) {
	t.Helper()

	if len(expectedPackages) != len(actualPackages) {
		t.Errorf(
			"Expected to get %d %s, but got %d",
			len(expectedPackages),
			output.Form(len(expectedPackages), "package", "packages"),
			len(actualPackages),
		)
	}

	missingActualPackages := FindMissingPackages(t, actualPackages, expectedPackages, ignoreLocations)
	missingExpectedPackages := FindMissingPackages(t, expectedPackages, actualPackages, ignoreLocations)

	if len(missingActualPackages) != 0 {
		for _, unexpectedPackage := range missingActualPackages {
			t.Errorf("Did not expect: %s", PackageToString(unexpectedPackage))
		}
	}

	if len(missingExpectedPackages) != 0 {
		for _, unexpectedPackage := range missingExpectedPackages {
			t.Errorf("Did not find:   %s", PackageToString(unexpectedPackage))
		}
	}
}

func ExpectPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) {
	t.Helper()

	InnerExpectPackages(t, actualPackages, expectedPackages, false)
}

func ExpectPackagesWithoutLocations(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails) {
	t.Helper()

	InnerExpectPackages(t, actualPackages, expectedPackages, true)
}

func GetTestContext() lockfile.ScanContext {
	r, _ := reporter.New("cyclonedx-1-5", os.Stdout, os.Stderr, reporter.ErrorLevel, true)
	return lockfile.ScanContext{Reporter: r}
}
