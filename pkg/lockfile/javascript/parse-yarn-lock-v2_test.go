package javascript_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestParseYarnLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseYarnLock("../fixtures/yarn/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v2_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseYarnLock("../fixtures/yarn/empty.v2.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v2_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/one-package.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

//nolint:paralleltest
func TestParseYarnLock_v2_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock packageJSONMatcher to fail
	matcherError := errors.New("packageJSONMatcher failed")
	javascript.YarnExtractor.Matchers = []lockfile.Matcher{testutil.FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/one-package.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})

	// Reset packageJSONMatcher mock
	testutil.MockAllMatchers()
}

func TestParseYarnLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/two-packages.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "compare-func",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_WithQuotes(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-quotes.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "compare-func",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_MultipleVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/multiple-versions.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"4"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.1.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.1.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.3.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.3.2"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "4.3.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.3.3"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "2.6.9",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.6.9"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "debug",
			Version:        "3.2.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^3.2.7"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/scoped-packages.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/cli",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.4.4"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.16.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.16.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.12.13"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.16.7",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.16.7"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/compat-data",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.13.11"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/compat-data",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.16.4"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/compat-data",
			Version:        "7.16.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.16.8"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_WithPrerelease(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-prerelease.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@nicolo-ribaudo/chokidar-2",
			Version:        "2.1.8-no-fsevents.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"2.1.8-no-fsevents.3"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "gensync",
			Version:        "1.0.0-beta.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0-beta.2"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_WithBuildString(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-build-string.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			Commit:         "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v2_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/commits.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@my-scope/my-first-package",
			Version:        "0.0.6",
			PackageManager: models.Yarn,
			TargetVersions: []string{"my-scope/my-first-package#commit=0b824c650d3a03444dbcf2b27a5f3566f6e41358"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "0b824c650d3a03444dbcf2b27a5f3566f6e41358",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-second-package",
			Version:        "0.2.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"my-org/my-second-package#commit=59e2127b9f9d4fda5f928c4204213b3502cd5bb0"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "59e2127b9f9d4fda5f928c4204213b3502cd5bb0",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@typegoose/typegoose",
			Version:        "7.2.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/typegoose/typegoose.git#main"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "3ed06e5097ab929f69755676fee419318aaec73a",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "vuejs",
			Version:        "2.5.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/vuejs/vue.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "0948d999f2fddf9f90991956493f976273c5da1f",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-third-package",
			Version:        "0.16.1-dev",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/my-org/my-third-package#everything"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "5675a0aed98e067ff6ecccc5ac674fe8995960e0",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-node-sdk",
			Version:        "1.1.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+https://github.com/my-org/my-node-sdk.git#v1.1.0"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "053dea9e0b8af442d8f867c8e690d2fb0ceb1bf5",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "is-really-great",
			Version:        "1.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"ssh://git@github.com:my-org/is-really-great.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "191eeef50c584714e1fb8927d17ee72b3b8c97c4",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/files.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "my-package",
			Version:        "0.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"../../deps/my-local-package"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v2_WithAliases(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-aliases.v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "@babel/helper-validator-identifier",
			Version:        "7.22.20",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "6.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "5.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v2_WithDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-dependencies-v2.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			Commit:         "f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a",
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}
	expected[0].Dependencies = append(expected[0].Dependencies, &expected[1])

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

// Test case: workspace-same-lib-and-version demonstrates shared dependencies:
// Root: no dependencies
// workspace-1: semver ^7.3.2
// workspace-2: semver ^7.3.2 (same as workspace-1)
func TestParseYarnLock_v2_WorkspacesSameLibSameVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/yarn.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-same-lib-and-version/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	workspace1path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/workspace-1/package.json"))
	workspace2path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/nested/workspace-2/package.json"))
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace2path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace2path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}

// Test case: workspace-same-lib-different-version demonstrates semver conflicts:
// Root: semver ^7.3.4
// workspace-1: semver ^7.3.3
// workspace-2: semver ^6.0.0
func TestParseYarnLock_v2_WorkspacesSameLibDifferentVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/yarn.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-same-lib-different-version/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/package.json"))
	workspace1path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/workspace-1/package.json"))
	workspace2path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/nested/workspace-2/package.json"))
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.4"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 5, End: 23},
				Filename: rootPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 6, End: 12},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 22},
				Filename: rootPath,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.3"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace2path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace2path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}

// Test case: workspace-complex demonstrates multi-workspace dependency conflicts:
// Root: semver ^4.3.0, group-dependencies 0.0.11
// workspace-1: semver ^7.3.2, picocolors ^0.2.1
// workspace-2: semver ^6.3.0
// workspace-3: semver ^5.0.0, picocolors ^1.1.1
func TestParseYarnLock_v2_WorkspacesComplex(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/yarn.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-complex/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/package.json"))
	workspace1Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-1/package.json"))
	workspace2Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/nested/workspace-2/package.json"))
	workspace3Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-3/package.json"))

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "group-dependencies",
			Version:        "0.0.11",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.11"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 5, End: 35},
				Filename: rootPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 6, End: 24},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 28, End: 34},
				Filename: rootPath,
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
			Dependencies: []*lockfile.PackageDetails{
				{
					Name:           "colors",
					Version:        "1.4.0",
					TargetVersions: []string{"^1.4.0"},
					PackageManager: models.Yarn,
					Ecosystem:      models.EcosystemNPM,
					DepGroups:      []string{"dev"},
					Dependencies:   make([]*lockfile.PackageDetails, 0),
				},
			},
		},
		{
			Name:           "colors",
			Version:        "1.4.0",
			TargetVersions: []string{"^1.4.0"},
			PackageManager: models.Yarn,
			Ecosystem:      models.EcosystemNPM,
			BlockLocation:  models.FilePosition{},
			IsDirect:       false, // is a dependency of group-dependencies@0.0.11
			DepGroups:      []string{"dev"},
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "4.3.6",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 23},
				Filename: rootPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 6, End: 12},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 16, End: 22},
				Filename: rootPath,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "picocolors",
			Version:        "0.2.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^0.2.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: workspace1Path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: workspace1Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: workspace1Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1Path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2Path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace2Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace2Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "picocolors",
			Version:        "1.1.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.1.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: workspace3Path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: workspace3Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: workspace3Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "5.7.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace3Path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace3Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace3Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}
