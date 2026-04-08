package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const packageJSONLock = `
{
  "name": "example",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEf3Q8XQ..."
    }
  }
}
`

const yarnLock = `
# yarn lockfile v1
lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-v2kDEf3Q8XQ...
`

func Test_scanDir(t *testing.T) {
	t.Parallel()

	// Setup temporary directory
	tempDir := t.TempDir()

	// Create test files and directories
	_ = os.WriteFile(filepath.Join(tempDir, "package-lock.json"), []byte(packageJSONLock), 0600)
	_ = os.WriteFile(filepath.Join(tempDir, "yarn.lock"), []byte(yarnLock), 0600)
	_ = os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "subdir", "package-lock.json"), []byte(packageJSONLock), 0600)

	// Mock reporter
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Verbosef(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()

	// Call scanDir without exclusion
	var excludedGlobs []string
	var configExcludedGlobs []string
	enabledParsers := initializeEnabledParsers([]string{}, mockReporter)
	packages, artifacts, err := scanDir(mockReporter, tempDir, tempDir, true, false, enabledParsers, excludedGlobs, configExcludedGlobs)

	// Validate results
	require.NoError(t, err)
	assert.Len(t, packages, 3) // matched 3 files, at all locations, no exclusion
	assert.Empty(t, artifacts)

	// Exclude all files in the subdir
	excludedGlobs = []string{filepath.Join("subdir", "*")}
	packages, artifacts, err = scanDir(mockReporter, tempDir, tempDir, true, false, enabledParsers, excludedGlobs, configExcludedGlobs)

	require.NoError(t, err)
	assert.Len(t, packages, 2) // Only package-lock.json and yarn.lock should be scanned (subdir/package-lock.json is excluded)
	assert.Empty(t, artifacts)

	// Exclude all files in the subdir and yarn.lock (precisely one file)
	excludedGlobs = []string{filepath.Join("subdir", "*"), "yarn.lock"}
	packages, artifacts, err = scanDir(mockReporter, tempDir, tempDir, true, false, enabledParsers, excludedGlobs, configExcludedGlobs)

	require.NoError(t, err)
	assert.Len(t, packages, 1) // Only package-lock.json should be scanned (yarn.lock and subdir/package-lock.json is excluded)
	assert.Empty(t, artifacts)
}

func Test_scanDir_ConfigExclusionsUseRepositoryRoot(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	scanDirPath := filepath.Join(repoRoot, "subdir")

	require.NoError(t, os.Mkdir(scanDirPath, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repoRoot, "package-lock.json"), []byte(packageJSONLock), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDirPath, "package-lock.json"), []byte(packageJSONLock), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDirPath, "yarn.lock"), []byte(yarnLock), 0o600))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Verbosef(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()

	enabledParsers := initializeEnabledParsers([]string{}, mockReporter)
	packages, artifacts, err := scanDir(mockReporter, scanDirPath, repoRoot, true, false, enabledParsers, nil, []string{"subdir/*"})

	require.NoError(t, err)
	assert.Empty(t, packages)
	assert.Empty(t, artifacts)
}

func Test_scanDir_ConfigExclusionsSupportPrefixAndDoublestarMatching(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	scanDirPath := filepath.Join(repoRoot, "subdir")

	require.NoError(t, os.MkdirAll(filepath.Join(scanDirPath, "dist"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(scanDirPath, "distribution"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(scanDirPath, "nested"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(scanDirPath, "dist", "package-lock.json"), []byte(packageJSONLock), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDirPath, "distribution", "package-lock.json"), []byte(packageJSONLock), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(scanDirPath, "nested", "yarn.lock"), []byte(yarnLock), 0o600))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Verbosef(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()

	enabledParsers := initializeEnabledParsers([]string{}, mockReporter)
	packages, artifacts, err := scanDir(
		mockReporter,
		scanDirPath,
		repoRoot,
		true,
		false,
		enabledParsers,
		nil,
		[]string{"subdir/dist", "subdir/**/*.lock"},
	)

	require.NoError(t, err)
	assert.Len(t, packages, 1)
	assert.Equal(t, "package-lock.json", filepath.Base(packages[0].Source.Path))
	assert.Contains(t, packages[0].Source.Path, filepath.Join("distribution", "package-lock.json"))
	assert.Empty(t, artifacts)
}

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
