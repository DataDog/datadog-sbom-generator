package javascript_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestPackageJSONExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "empty path", path: "", want: false},
		{name: "bare package.json", path: "package.json", want: true},
		{name: "nested package.json", path: "path/to/my/package.json", want: true},
		{name: "package.json as directory prefix", path: "path/to/my/package.json/file", want: false},
		{name: "package.json with suffix", path: "path/to/my/package.json.bak", want: false},
		{name: "package-lock.json is not package.json", path: "package-lock.json", want: false},
		{name: "inside node_modules", path: "node_modules/lodash/package.json", want: false},
		{name: "inside nested node_modules", path: "path/to/node_modules/foo/package.json", want: false},
		{name: "node_modules windows path", path: "path\\to\\node_modules\\foo\\package.json", want: false},
		{name: "my-node_modules is not node_modules", path: "my-node_modules/foo/package.json", want: true},
		{name: "nested my-node_modules is not node_modules", path: "path/to/my-node_modules/foo/package.json", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := javascript.PackageJSONExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) got = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParsePackageJSON_FileDoesNotExist(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/does-not-exist/package.json"))
	packages, err := javascript.ParsePackageJSON(path)

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/invalid/package.json"))
	packages, err := javascript.ParsePackageJSON(path)

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_Empty(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/empty/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_Basic(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/basic/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "lodash",
			Version:                      "",
			VersionRange:                 "^4.17.21",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_AllDepTypes(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/all-dep-types/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "express",
			Version:                      "",
			VersionRange:                 "^4.18.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "jest",
			Version:                      "",
			VersionRange:                 "~29.7.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"dev"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "fsevents",
			Version:                      "2.3.3",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"optional"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_WithSiblingNpmLockfile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/with-npm-lockfile/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_WithSiblingLockfileButLockfileParsersDisabled(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/with-npm-lockfile/package.json"))

	ctx := testutil.GetTestContext()
	ctx.EnabledParsers = map[string]bool{"package.json": true}

	packages, err := lockfile.ExtractFromFileWithContext(path, javascript.PackageJSONExtractor{}, ctx)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "lodash",
			Version:                      "",
			VersionRange:                 "^4.17.21",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_WithSiblingYarnLock(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/with-yarn-lock/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_WithSiblingPnpmLock(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/with-pnpm-lock/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParsePackageJSON_ComplexVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/complex-versions/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "pinned",
			Version:                      "1.0.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "eq-pinned",
			Version:                      "2.0.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "caret",
			Version:                      "",
			VersionRange:                 "^2.3.4",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "tilde",
			Version:                      "",
			VersionRange:                 "~1.5.3",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "range",
			Version:                      "",
			VersionRange:                 ">=1.0.0 <2.0.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "real-pkg",
			Version:                      "3.0.0",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "wildcard-star",
			Version:                      "",
			VersionRange:                 "*",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "wildcard-x",
			Version:                      "",
			VersionRange:                 "x",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_AliasCollision(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/alias-collision/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "react",
			Version:                      "17.0.2",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
		{
			Name:                         "react",
			Version:                      "18.3.1",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_AliasRangeCollision(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	// react17 < react18 alphabetically, so react17's range (^17) wins deterministically.
	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/alias-range-collision/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:                         "react",
			VersionRange:                 "^17",
			PackageManager:               models.NPM,
			Ecosystem:                    models.EcosystemNPM,
			IsDirect:                     true,
			RequiresTransitiveEnrichment: true,
			DepGroups:                    []string{"prod"},
			LocationRole:                 models.LocationRoleManifest,
		},
	})
}

func TestParsePackageJSON_WorkspaceWithRootLockfile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	fixtureRoot := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/workspace-with-root-lockfile"))
	path := filepath.Join(fixtureRoot, "packages", "foo", "package.json")

	ctx := testutil.GetTestContext()
	ctx.RootDir = fixtureRoot

	packages, err := lockfile.ExtractFromFileWithContext(path, javascript.PackageJSONExtractor{}, ctx)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

// TestParsePackageJSON_SetsManifestMetadata verifies fields ignored by
// ExpectPackagesWithoutLocations.
func TestParsePackageJSON_SetsManifestMetadata(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json-extractor/all-dep-types/package.json"))
	packages, err := javascript.ParsePackageJSON(path)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	if len(packages) == 0 {
		t.Fatal("expected packages, got none")
	}

	for _, pkg := range packages {
		if pkg.LocationRole != models.LocationRoleManifest {
			t.Errorf("package %s@%s: LocationRole = %q, want %q",
				pkg.Name, pkg.Version, pkg.LocationRole, models.LocationRoleManifest)
		}
		if !pkg.RequiresTransitiveEnrichment {
			t.Errorf("package %s@%s: RequiresTransitiveEnrichment = false, want true", pkg.Name, pkg.Version)
		}
	}
}

func TestParsePackageJSON_WorkspaceWithRelativeRootDir(t *testing.T) {
	t.Parallel()

	fixtureRoot := filepath.FromSlash("../fixtures/package-json-extractor/workspace-with-root-lockfile")
	absFixtureRoot, err := filepath.Abs(fixtureRoot)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	path := filepath.Join(absFixtureRoot, "packages", "foo", "package.json")

	ctx := testutil.GetTestContext()
	ctx.RootDir = fixtureRoot

	packages, err := lockfile.ExtractFromFileWithContext(path, javascript.PackageJSONExtractor{}, ctx)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}
