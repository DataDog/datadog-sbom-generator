package testutil

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
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

	return fmt.Sprintf(
		"%s@%s {versionRange=%q ecosystem=%q targetVersions=%v packageManager=%q commit=%q depGroups=%v exclusions=%v targetFrameworks=%v isDirect=%t requiresTransitiveEnrichment=%t blockLocation=%s nameLocation=%s versionLocation=%s}",
		pkg.Name,
		pkg.Version,
		pkg.VersionRange,
		pkg.Ecosystem,
		pkg.TargetVersions,
		pkg.PackageManager,
		commit,
		pkg.DepGroups,
		pkg.Exclusions,
		pkg.TargetFrameworks,
		pkg.IsDirect,
		pkg.RequiresTransitiveEnrichment,
		formatLoc(pkg.BlockLocation),
		formatLocPtr(pkg.NameLocation),
		formatLocPtr(pkg.VersionLocation),
	)
}

func formatLoc(loc models.FilePosition) string {
	return fmt.Sprintf("{Line:%d Column:%d Filename:%q}", loc.Line, loc.Column, loc.Filename)
}

func formatLocPtr(loc *models.FilePosition) string {
	if loc == nil {
		return "<nil>"
	}

	return fmt.Sprintf("{Line:%d Column:%d Filename:%q}", loc.Line, loc.Column, loc.Filename)
}

func HasPackage(t *testing.T, expectedPkgs []lockfile.PackageDetails, currentPkg lockfile.PackageDetails, ignoreLocations bool) bool {
	t.Helper()

	for _, expectedPkg := range expectedPkgs {
		var ignore []string
		if ignoreLocations {
			ignore = []string{"BlockLocation", "LocationRole", "NameLocation", "VersionLocation"}
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

func InnerExpectPackages(t *testing.T, actualPackages []lockfile.PackageDetails, expectedPackages []lockfile.PackageDetails, ignoreLocations bool) {
	t.Helper()

	cmpOpts := cmpOptions(ignoreLocations)

	// packages are index by 'name@version' - a give 'name@version' can be reported at several locations
	expectedByKey := indexExpected(expectedPackages)

	for _, pkg := range actualPackages {
		matchAndReportOne(t, pkg, expectedByKey[packageKey(pkg)], cmpOpts)
	}

	reportMissingExpected(t, expectedByKey)
}

func cmpOptions(ignoreLocations bool) []cmp.Option {
	if !ignoreLocations {
		return nil
	}

	return []cmp.Option{
		cmpopts.IgnoreFields(lockfile.PackageDetails{}, "BlockLocation", "LocationRole", "NameLocation", "VersionLocation"),
	}
}

type expectedEntry struct {
	pkg     lockfile.PackageDetails
	matched bool
}

func packageKey(p lockfile.PackageDetails) string {
	return p.Name + "@" + p.Version
}

func indexExpected(expectedPackages []lockfile.PackageDetails) map[string][]*expectedEntry {
	expectedByKey := make(map[string][]*expectedEntry, len(expectedPackages))
	for _, ep := range expectedPackages {
		e := &expectedEntry{pkg: ep}
		k := packageKey(ep)
		expectedByKey[k] = append(expectedByKey[k], e)
	}

	return expectedByKey
}

func matchAndReportOne(
	t *testing.T,
	pkg lockfile.PackageDetails,
	candidates []*expectedEntry,
	cmpOpts []cmp.Option,
) {
	t.Helper()

	if len(candidates) == 0 {
		t.Errorf("Did not expect: %s", PackageToString(pkg))
		return
	}

	if len(candidates) == 1 {
		c := candidates[0]
		c.matched = true

		if diff := cmp.Diff(c.pkg, pkg, cmpOpts...); diff != "" {
			t.Errorf("Package mismatch for %s (-expected +actual): %s", packageKey(pkg), diff)
		}

		return
	}

	for _, c := range candidates {
		if cmp.Equal(c.pkg, pkg, cmpOpts...) {
			c.matched = true
			return
		}
	}

	t.Errorf("Did not expect: %s", PackageToString(pkg))
}

func reportMissingExpected(t *testing.T, expectedByKey map[string][]*expectedEntry) {
	t.Helper()

	for _, candidates := range expectedByKey {
		for _, c := range candidates {
			if !c.matched {
				t.Errorf("Did not find:   %s", PackageToString(c.pkg))
			}
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
