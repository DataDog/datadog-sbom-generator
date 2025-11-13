package lockfile_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
)

func TestParseNpmLock_v2_FileDoesNotExist(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/does-not-exist"))
	packages, err := lockfile.ParseNpmLock(path)

	expectErrIs(t, err, fs.ErrNotExist)
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_InvalidJson(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/not-json.txt"))
	packages, err := lockfile.ParseNpmLock(path)

	expectErrContaining(t, err, "could not extract from")
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_NoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/empty.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseNpmLock_v2_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/one-package.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			TargetVersions: []string{"^1.0.0"},
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

//nolint:paralleltest
func TestParseNpmLock_v2_OnePackage_MatcherFailed(t *testing.T) {
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
	lockfile.NpmExtractor.Matchers = []lockfile.Matcher{FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/one-package.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
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
	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
	})

	// Reset packageJSONMatcher mock
	MockAllMatchers()
}

func TestParseNpmLock_v2_OnePackageDev(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/one-package-dev.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_LinkDependency(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/link-dependency.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/two-packages.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/scoped-packages.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.0.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_NestedDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/nested-dependencies.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "postcss",
			Version:        "6.0.23",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "postcss",
			Version:        "7.0.16",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "postcss-calc",
			Version:        "7.0.1",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "supports-color",
			Version:        "6.1.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_NestedDependenciesDup(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/nested-dependencies-dup.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "supports-color",
			Version:        "6.1.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "supports-color",
			Version:        "2.0.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/commits.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@segment/analytics.js-integration-facebook-pixel",
			Version:        "2.4.1",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"github:segmentio/analytics.js-integrations#2.4.1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "3b1bb80b302c2e552685dc8a029797ec832ea7c9",
		},
		{
			Name:           "ansi-styles",
			Version:        "1.0.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
		},
		{
			Name:           "babel-preset-php",
			Version:        "1.1.1",
			PackageManager: models.NPM,
			TargetVersions: []string{"gitlab:kornelski/babel-preset-php#main"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-1",
			Version:        "3.0.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-1",
			Version:        "3.0.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "be5935f8d2595bcd97b05718ef1eeae08d812e10",
			DepGroups:      []string{"dev"},
			IsDirect:       false,
		},
		{
			Name:           "is-number-2",
			Version:        "2.0.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git#d5ac058"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-2",
			Version:        "2.0.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "82dcc8e914dabd9305ab9ae580709a7825e824f5",
			DepGroups:      []string{"dev"},
			IsDirect:       false,
		},
		{
			Name:           "is-number-3",
			Version:        "2.0.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"https://github.com/jonschlinkert/is-number.git#2.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-3",
			Version:        "3.0.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "82ae8802978da40d7f1be5ad5943c9e550ab2c89",
			DepGroups:      []string{"dev"},
			IsDirect:       false,
		},
		{
			Name:           "is-number-4",
			Version:        "3.0.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"git+ssh://git@github.com:jonschlinkert/is-number.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "is-number-5",
			Version:        "3.0.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"https://dummy-token@github.com/jonschlinkert/is-number.git#main"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "postcss-calc",
			Version:        "7.0.1",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			DepGroups:      []string{"prod"},
			IsDirect:       false,
		},
		{
			Name:           "raven-js",
			Version:        "",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"getsentry/raven-js#3.23.1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "c2b377e7a254264fd4a1fe328e4e3cfc9e245570",
		},
		{
			Name:           "slick-carousel",
			Version:        "1.7.1",
			PackageManager: models.NPM,
			TargetVersions: []string{"git://github.com/brianfryer/slick"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "280b560161b751ba226d50c7db1e0a14a78c2de0",
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/files.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "etag",
			Version:        "1.8.0",
			PackageManager: models.NPM,
			TargetVersions: []string{"deps/etag"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "abbrev",
			Version:        "1.0.9",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "abbrev",
			Version:        "2.3.4",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParseNpmLock_v2_Alias(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/alias.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/code-frame",
			Version:        "7.0.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "string-width",
			Version:        "4.2.0",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^4.2.0"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "string-width",
			Version:        "5.1.2",
			PackageManager: models.NPM,
			DepGroups:      []string{"prod"},
			TargetVersions: []string{"^5.1.2"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_OptionalPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/npm/optional-package.v2.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.NPM,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"optional", "prod"},
		},
		{
			Name:           "supports-color",
			Version:        "5.5.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"dev", "optional"},
		},
	})
}

func TestParseNpmLock_v2_SamePackageDifferentGroups(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParseNpmLock("fixtures/npm/same-package-different-groups.v2.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "eslint",
			Version:        "1.2.3",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"dev"},
		},
		{
			Name:           "table",
			Version:        "1.0.0",
			DepGroups:      []string{"prod"},
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "ajv",
			Version:        "5.5.2",
			PackageManager: models.NPM,
			DepGroups:      []string{"dev", "optional", "prod"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseNpmLock_v2_Workspaces(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspaces/package-lock.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/workspaces/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	workspace1path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspaces/folder/package.json"))
	workspace2path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspaces/other-folder/workspace-2/package.json"))

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.NPM,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 25},
				Filename: workspace1path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 24},
				Filename: workspace1path,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "7.6.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
	})
}

func TestParseNpmLock_v2_WorkspacesSameLibSameVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-and-version/package-lock.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/workspace-same-lib-and-version/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	workspace2path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-and-version/other-folder/workspace-2/package.json"))
	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.6.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "workspace-1",
			Version:        "1.0.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParseNpmLock_v2_WorkspacesSameLibDifferentVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-different-version/package-lock.json"))
	packages, err := lockfile.ParseNpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("fixtures/package-json/workspace-same-lib-different-version/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	projectpath := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-different-version/package.json"))
	anotherfolderpath := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-different-version/another-folder/package.json"))
	folderpath := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-different-version/folder/package.json"))
	workspace2path := filepath.FromSlash(filepath.Join(dir, "fixtures/package-json/workspace-same-lib-different-version/other-folder/workspace-2/package.json"))

	expectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: folderpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: folderpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: folderpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "picocolors",
			Version:        "0.2.1",
			PackageManager: models.NPM,
			TargetVersions: []string{"^0.2.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: folderpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: folderpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: folderpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "picocolors",
			Version:        "1.1.1",
			PackageManager: models.NPM,
			TargetVersions: []string{"^1.1.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: anotherfolderpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: anotherfolderpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: anotherfolderpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.NPM,
			TargetVersions: []string{"^6.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "5.7.2",
			PackageManager: models.NPM,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: anotherfolderpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: anotherfolderpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: anotherfolderpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "4.3.6",
			PackageManager: models.NPM,
			TargetVersions: []string{"^4.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 5, End: 23},
				Filename: projectpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 6, End: 12},
				Filename: projectpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 22},
				Filename: projectpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "group-dependencies",
			Version:        "0.0.11",
			PackageManager: models.NPM,
			TargetVersions: []string{"0.0.11"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 35},
				Filename: projectpath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 6, End: 24},
				Filename: projectpath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 28, End: 34},
				Filename: projectpath,
			},
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "colors",
			Version:        "1.4.0",
			PackageManager: models.NPM,
			Ecosystem:      models.EcosystemNPM,
			BlockLocation:  models.FilePosition{},
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
	})
}
