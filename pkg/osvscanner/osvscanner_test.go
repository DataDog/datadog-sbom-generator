package osvscanner

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"

	"github.com/stretchr/testify/assert"
)

func Test_getDirectPackagePurls(t *testing.T) {
	t.Parallel()

	scannedPackages := []lockfile.PackageDetails{
		{
			PURL:     "pkg:maven/org.example/pkg1@1.0.0",
			IsDirect: true,
		},
		{
			PURL:     "pkg:maven/org.example/pkg2@2.0.0",
			IsDirect: true,
		},
		{
			// duplicate of pkg2 to test uniqueness
			PURL:     "pkg:maven/org.example/pkg2@2.0.0",
			IsDirect: true,
		},
		{
			PURL:     "pkg:maven/org.example/pkg3@3.0.0",
			IsDirect: false,
		},
	}

	directPurls := getDirectPackagePurls(scannedPackages)

	assert.Len(t, directPurls, 2)
	assert.Contains(t, directPurls, "pkg:maven/org.example/pkg1@1.0.0")
	assert.Contains(t, directPurls, "pkg:maven/org.example/pkg2@2.0.0")
	assert.NotContains(t, directPurls, "pkg:maven/org.example/pkg3@3.0.0")
}

const (
	ValidVersion          = "1.0.0"
	InvalidRangedVersion1 = "<0.27.6"
	InvalidRangedVersion2 = ">=0.27.6"
	InvalidRangedVersion3 = ">=0.15.0,<0.16.0"
)

func Test_packageHasRangedVersion(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		version       string
		includesRange bool
	}{
		{
			name:          "no ranged version",
			version:       ValidVersion,
			includesRange: false,
		},
		{
			name:          "contains <",
			version:       InvalidRangedVersion1,
			includesRange: true,
		},
		{
			name:          "contains >",
			version:       InvalidRangedVersion2,
			includesRange: true,
		},
		{
			name:          "contains all",
			version:       InvalidRangedVersion3,
			includesRange: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.includesRange, packageHasRangedVersion(lockfile.PackageDetails{Version: tc.version}))
		})
	}
}

func Test_sanitizeScannedPackages_Empty(t *testing.T) {
	t.Parallel()

	scannedPackages := []lockfile.PackageDetails{}
	sanitizedPackages, errors := sanitizeScannedPackages(scannedPackages)

	assert.Empty(t, sanitizedPackages)
	assert.Empty(t, errors)
}

func Test_sanitizeScannedPackages_RangedVersionAreFiltered(t *testing.T) {
	t.Parallel()

	scannedPackages := []lockfile.PackageDetails{
		{Version: InvalidRangedVersion1},
		{Version: InvalidRangedVersion2},
		{Version: InvalidRangedVersion3},
	}

	sanitizedPackages, errors := sanitizeScannedPackages(scannedPackages)

	assert.Empty(t, sanitizedPackages)
	assert.Len(t, errors, 3)
}
