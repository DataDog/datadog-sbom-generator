package javascript_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestParsePnpmLock_v9_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/no-packages.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_v9_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/one-package.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn",
			Version:        "8.11.3",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.11.3"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParsePnpmLock_v9_OnePackage_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/one-package.v9.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}

	pkg := packages[0]
	if pkg.BlockLocation.Line.Start == 0 {
		t.Errorf("Expected BlockLocation.Line.Start > 0 for %s, got 0", pkg.Name)
	}
	if pkg.BlockLocation.Line.End == 0 {
		t.Errorf("Expected BlockLocation.Line.End > 0 for %s, got 0", pkg.Name)
	}
	if pkg.BlockLocation.Column.Start == 0 {
		t.Errorf("Expected BlockLocation.Column.Start > 0 for %s, got 0", pkg.Name)
	}
	if pkg.BlockLocation.Column.End == 0 {
		t.Errorf("Expected BlockLocation.Column.End > 0 for %s, got 0", pkg.Name)
	}
	if pkg.BlockLocation.Filename != path {
		t.Errorf("Expected BlockLocation.Filename = %s, got %s", path, pkg.BlockLocation.Filename)
	}

	// acorn@8.11.3 is at lines 17-20 in one-package.v9.yaml (last non-empty line before "snapshots:")
	assert.Equal(t, 17, pkg.BlockLocation.Line.Start)
	assert.Equal(t, 20, pkg.BlockLocation.Line.End)
}

func TestParsePnpmLock_v9_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/one-package-dev.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn",
			Version:        "8.11.3",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.11.3"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"dev"},
		},
	})
}

func TestParsePnpmLock_v9_ScopedPackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/scoped-packages.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParsePnpmLock_v9_PeerDependencies(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/peer-dependencies.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "acorn-jsx",
			Version:        "5.3.2",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.3.2"},

			Ecosystem: models.EcosystemNPM,
			IsDirect:  true,
			DepGroups: []string{"prod"},
		},
		{
			Name:           "acorn",
			Version:        "8.11.3",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParsePnpmLock_v9_PeerDependenciesAdvanced(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/peer-dependencies-advanced.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@eslint-community/eslint-utils",
			Version:        "4.4.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@eslint/eslintrc",
			Version:        "2.1.4",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@typescript-eslint/eslint-plugin",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.12.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@typescript-eslint/parser",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.12.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@typescript-eslint/type-utils",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@typescript-eslint/typescript-estree",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "@typescript-eslint/utils",
			Version:        "5.62.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "debug",
			Version:        "4.3.4",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "eslint",
			Version:        "8.57.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.0.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "has-flag",
			Version:        "4.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "supports-color",
			Version:        "7.2.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "tsutils",
			Version:        "3.21.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "typescript",
			Version:        "4.9.5",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^4.0.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "chalk",
			Version:        "4.1.2",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParsePnpmLock_v9_MultipleVersions(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/multiple-versions.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "uuid",
			Version:        "8.0.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       false,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "uuid",
			Version:        "8.3.2",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.0.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "aws-sdk",
			Version:        "2.1692.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			TargetVersions: []string{"^2.1087.0"},
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
	})
}

func TestParsePnpmLock_v9_Commits(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/commits.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "ansi-regex",
			Version:        "6.0.1",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"git@github.com/chalk/ansi-regex.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "02fa893d619d3da85411acc8fd4e2eea0e95a9d9",
			DepGroups:      []string{"prod"},
			IsDirect:       true,
		},
		{
			Name:           "is-number",
			Version:        "7.0.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"github:jonschlinkert/is-number#master"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"prod"},
			Commit:         "98e8ff1da1a89f93d1397a24d7413ed15421c139",
			IsDirect:       true,
		},
	})
}

// TestParsePnpmLock_v9_Commits_BlockLocation verifies that git/tarball dependencies
// (whose packages: key uses a full URL like "ansi-regex@https://codeload.github.com/...")
// correctly resolve their BlockLocation even though lookupPnpmPosition receives a cleaned
// semver version, not the raw URL.
func TestParsePnpmLock_v9_Commits_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/commits.v9.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	for _, pkg := range packages {
		assert.Positive(t, pkg.BlockLocation.Line.Start, "BlockLocation.Line.Start should be > 0 for %s", pkg.Name)
		assert.Positive(t, pkg.BlockLocation.Line.End, "BlockLocation.Line.End should be > 0 for %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename, "BlockLocation.Filename should match for %s", pkg.Name)
	}
}

func TestParsePnpmLock_v9_MixedGroups_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/mixed-groups.v9.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// All packages should have BlockLocation set
	for _, pkg := range packages {
		assert.Greater(t, pkg.BlockLocation.Line.Start, 0, "BlockLocation.Line.Start should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Line.End, 0, "BlockLocation.Line.End should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Column.Start, 0, "BlockLocation.Column.Start should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Column.End, 0, "BlockLocation.Column.End should be > 0 for %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename, "BlockLocation.Filename should match for %s", pkg.Name)
	}
}

// TestParsePnpmLock_v9_PeerDependenciesAdvanced_BlockLocation verifies that scoped packages
// (whose YAML keys are surrounded by single quotes, e.g. '@scope/pkg@1.0.0':) get their
// BlockLocation correctly populated. This is a regression test for the bug where the single
// quotes were stored as part of the position map key, causing lookups to miss.
func TestParsePnpmLock_v9_PeerDependenciesAdvanced_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/peer-dependencies-advanced.v9.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Packages that appear in the packages: section should all have BlockLocation set.
	// chalk@4.1.2 only appears in snapshots: (not packages:) so it is the only exception.
	packagesWithoutPosition := map[string]bool{
		"chalk@4.1.2": true,
	}

	for _, pkg := range packages {
		key := pkg.Name + "@" + pkg.Version
		if packagesWithoutPosition[key] {
			continue
		}
		assert.Positive(t, pkg.BlockLocation.Line.Start, "BlockLocation.Line.Start should be > 0 for %s", pkg.Name)
		assert.Positive(t, pkg.BlockLocation.Line.End, "BlockLocation.Line.End should be > 0 for %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename, "BlockLocation.Filename should match for %s", pkg.Name)
	}
}

func TestParsePnpmLock_v9_MixedGroups(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParsePnpmLock("../fixtures/pnpm/mixed-groups.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "ansi-regex",
			Version:        "5.0.1",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"prod"},
			IsDirect:       true,
		},
		{
			Name:           "uuid",
			Version:        "8.3.2",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^8.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"optional"},
			IsDirect:       true,
		},
		{
			Name:           "is-number",
			Version:        "7.0.0",
			PackageManager: models.Pnpm,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
			DepGroups:      []string{"dev"},
			IsDirect:       true,
		},
	})
}

// Test case: workspace-same-lib-and-version demonstrates shared dependencies:
// Root: no dependencies
// workspace-1: semver ^7.3.2
// workspace-2: semver ^7.3.2 (same as workspace-1)
func TestParsePnpmLock_v9_WorkspacesSameLibSameVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/pnpm-lock.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
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
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
	})
}

// Test case: workspace-same-lib-different-version demonstrates semver conflicts:
// Root: semver ^7.3.4
// workspace-1: semver ^7.3.3
// workspace-2: semver ^6.0.0
func TestParsePnpmLock_v9_WorkspacesSameLibDifferentVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/pnpm-lock.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
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
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
	})
}

// Test case: workspace-complex demonstrates multi-workspace dependency conflicts:
// Root: semver ^4.3.0, group-dependencies 0.0.11
// workspace-1: semver ^7.3.2, picocolors ^0.2.1
// workspace-2: semver ^6.3.0
// workspace-3: semver ^5.0.0, picocolors ^1.1.1
func TestParsePnpmLock_v9_WorkspacesComplex(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/pnpm-lock.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
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
	lockfilePath := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/pnpm-lock.yaml"))
	workspace1Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-1/package.json"))
	workspace2Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/nested/workspace-2/package.json"))
	workspace3Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-3/package.json"))

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "group-dependencies",
			Version:        "0.0.11",
			PackageManager: models.Pnpm,
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
			DepGroups: []string{"dev", "dev"},
		},
		{
			Name:           "colors",
			Version:        "1.4.0",
			PackageManager: models.Pnpm,
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 45, End: 47},
				Column:   models.Position{Start: 3, End: 32},
				Filename: lockfilePath,
			},
			IsDirect:  false, // is a dependency of group-dependencies@0.0.11
			DepGroups: []string{"dev"},
		},
		{
			Name:           "semver",
			Version:        "4.3.6",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "picocolors",
			Version:        "0.2.1",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "picocolors",
			Version:        "1.1.1",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
		{
			Name:           "semver",
			Version:        "5.7.2",
			PackageManager: models.Pnpm,
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
			IsDirect:  true,
			DepGroups: []string{"prod", "prod"},
		},
	})
}

func TestParsePnpmLock_Legacy_OnePackage_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/one-package.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}

	pkg := packages[0]
	assert.Greater(t, pkg.BlockLocation.Line.Start, 0, "BlockLocation.Line.Start should be > 0")
	assert.Greater(t, pkg.BlockLocation.Line.End, 0, "BlockLocation.Line.End should be > 0")
	assert.Greater(t, pkg.BlockLocation.Column.Start, 0, "BlockLocation.Column.Start should be > 0")
	assert.Greater(t, pkg.BlockLocation.Column.End, 0, "BlockLocation.Column.End should be > 0")
	assert.Equal(t, path, pkg.BlockLocation.Filename)

	// /acorn/8.7.0 is at lines 11-15 in one-package.yaml
	assert.Equal(t, 11, pkg.BlockLocation.Line.Start)
	assert.Equal(t, 15, pkg.BlockLocation.Line.End)
}

func TestParsePnpmLock_Legacy_MultiplePackages_BlockLocation(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/pnpm/multiple-packages.yaml"))
	packages, err := javascript.ParsePnpmLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// All packages should have BlockLocation set
	for _, pkg := range packages {
		assert.Greater(t, pkg.BlockLocation.Line.Start, 0, "BlockLocation.Line.Start should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Line.End, 0, "BlockLocation.Line.End should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Column.Start, 0, "BlockLocation.Column.Start should be > 0 for %s", pkg.Name)
		assert.Greater(t, pkg.BlockLocation.Column.End, 0, "BlockLocation.Column.End should be > 0 for %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename, "BlockLocation.Filename should match for %s", pkg.Name)
	}
}
