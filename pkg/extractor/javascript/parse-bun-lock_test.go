package javascript_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestBunLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "empty path", path: "", want: false},
		{name: "bare bun.lock", path: "bun.lock", want: true},
		{name: "nested bun.lock", path: "path/to/my/bun.lock", want: true},
		{name: "wrong basename", path: "bun.lockb", want: false},
		{name: "trailing junk", path: "path/to/my/bun.lock/file", want: false},
		{name: "node_modules at root", path: "node_modules/dep/bun.lock", want: false},
		{name: "node_modules nested", path: "app/node_modules/dep/bun.lock", want: false},
		{name: "node_modules deep", path: "app/node_modules/dep/sub/bun.lock", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := javascript.BunExtractor.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseBunLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/empty.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseBunLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/one-package.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.Bun,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 53},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_ScopedPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/scoped-package.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.62.0",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 90},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_GitCommit(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/commits.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "raven-js",
			Version:        "",
			Commit:         "91ef2d4",
			PackageManager: models.Bun,
			TargetVersions: []string{"getsentry/raven-js#3.23.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 97},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_FileDependency(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/files.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "local-pkg",
			Version:        "",
			PackageManager: models.Bun,
			TargetVersions: []string{"file:../local-pkg"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 66},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_MultiplePackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/multiple-packages.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 5, End: 55},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
		{
			Name:           "typescript",
			Version:        "5.3.3",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 5, End: 90},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_SkipsWorkspacePackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/bun/workspace-package.lock"))
	packages, err := javascript.ParseBunLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 5, End: 55},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
		{
			Name:           "typescript",
			Version:        "5.3.3",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 5, End: 72},
				Filename: path,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseBunLock_MatchesPackageJSONRanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bunLockPath := filepath.Join(dir, models.BunFilePath.String())
	packageJSONPath := filepath.Join(dir, "package.json")

	err := os.WriteFile(bunLockPath, []byte(`{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "bun-ranges",
      "dependencies": {
        "lodash": "^4.17.21"
      },
      "devDependencies": {
        "typescript": "^5.0.0"
      }
    }
  },
  "packages": {
    "lodash": ["lodash@4.17.21", "", {}, "sha512-aaa"],
    "typescript": ["typescript@5.3.3", "", {}, "sha512-bbb"]
  }
}`), 0o600)
	if err != nil {
		t.Fatalf("could not write bun.lock fixture: %v", err)
	}

	err = os.WriteFile(packageJSONPath, []byte(`{
  "name": "bun-ranges",
  "dependencies": {
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}`), 0o600)
	if err != nil {
		t.Fatalf("could not write package.json fixture: %v", err)
	}

	packages, err := javascript.ParseBunLock(bunLockPath)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "typescript",
			Version:        "5.3.3",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"dev"},
		},
	})

	for _, pkg := range packages {
		if pkg.NameLocation == nil || pkg.VersionLocation == nil || pkg.BlockLocation.Filename != packageJSONPath {
			t.Errorf("expected %s to have package.json locations, got block=%+v name=%+v version=%+v", pkg.Name, pkg.BlockLocation, pkg.NameLocation, pkg.VersionLocation)
		}
	}
}

func TestParseBunLock_DoesNotApplyDirectRangeToTransitiveVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bunLockPath := filepath.Join(dir, models.BunFilePath.String())
	packageJSONPath := filepath.Join(dir, "package.json")

	err := os.WriteFile(bunLockPath, []byte(`{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "bun-duplicate-ranges",
      "dependencies": {
        "debug": "^4.3.4"
      }
    }
  },
  "packages": {
    "debug": ["debug@4.3.4", "", {}, "sha512-direct"],
    "compression/debug": ["debug@2.6.9", "", {}, "sha512-transitive"]
  }
}`), 0o600)
	if err != nil {
		t.Fatalf("could not write bun.lock fixture: %v", err)
	}

	err = os.WriteFile(packageJSONPath, []byte(`{
  "name": "bun-duplicate-ranges",
  "dependencies": {
    "debug": "^4.3.4"
  }
}`), 0o600)
	if err != nil {
		t.Fatalf("could not write package.json fixture: %v", err)
	}

	packages, err := javascript.ParseBunLock(bunLockPath)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "debug",
			Version:        "4.3.4",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.3.4"},
			Ecosystem:      models.EcosystemNPM,
			IsDirect:       true,
			DepGroups:      []string{"prod"},
		},
		{
			Name:           "debug",
			Version:        "2.6.9",
			PackageManager: models.Bun,
			TargetVersions: []string{},
			Ecosystem:      models.EcosystemNPM,
		},
	})

	// Headline behavior: with the PackageJSONMatcher active, the DIRECT debug@4.3.4
	// is enriched from package.json (LocationRole=manifest), but the TRANSITIVE
	// debug@2.6.9 (the "compression/debug" entry, never declared in package.json)
	// must retain its original bun.lock BlockLocation with LocationRole=lockfile.
	var direct, transitive *extractor.PackageDetails
	for i := range packages {
		switch packages[i].Version {
		case "4.3.4":
			direct = &packages[i]
		case "2.6.9":
			transitive = &packages[i]
		}
	}

	if assert.NotNil(t, transitive, "expected the transitive debug@2.6.9 package") {
		assert.False(t, transitive.IsDirect, "debug@2.6.9 should be transitive")
		assert.Equal(t, models.LocationRoleLockfile, transitive.LocationRole)
		assert.Equal(t, models.FilePosition{
			Line:     models.Position{Start: 13, End: 13},
			Column:   models.Position{Start: 5, End: 70},
			Filename: bunLockPath,
		}, transitive.BlockLocation)
	}

	// Contrast: the direct dependency is overwritten to the manifest location.
	if assert.NotNil(t, direct, "expected the direct debug@4.3.4 package") {
		assert.Equal(t, models.LocationRoleManifest, direct.LocationRole)
		if direct.BlockLocation.Filename != packageJSONPath {
			t.Errorf("expected direct debug@4.3.4 BlockLocation.Filename %q, got %q", packageJSONPath, direct.BlockLocation.Filename)
		}
	}
}

func TestParseBunLock_MalformedJSON(t *testing.T) {
	t.Parallel()

	_, err := javascript.ParseBunLock("../fixtures/bun/not-json.lock")
	if err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestParseBunLock_EmptyTuple(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/empty-tuple.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseBunLock_NonStringFirstElement(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/non-string-spec.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}
