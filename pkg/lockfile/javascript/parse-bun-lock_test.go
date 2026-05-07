package javascript_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseBunLock_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/one-package.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "wrappy",
			Version:        "1.0.2",
			PackageManager: models.Bun,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseBunLock_ScopedPackage(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/scoped-package.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/types",
			Version:        "5.62.0",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseBunLock_GitCommit(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/commits.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "raven-js",
			Version:        "",
			Commit:         "91ef2d4",
			PackageManager: models.Bun,
			TargetVersions: []string{"getsentry/raven-js#3.23.1"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseBunLock_FileDependency(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/files.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "local-pkg",
			Version:        "",
			PackageManager: models.Bun,
			TargetVersions: []string{"file:../local-pkg"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseBunLock_MultiplePackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/multiple-packages.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "typescript",
			Version:        "5.3.3",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
		},
	})
}

func TestParseBunLock_SkipsWorkspacePackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/workspace-package.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "lodash",
			Version:        "4.17.21",
			PackageManager: models.Bun,
			TargetVersions: []string{"^4.17.21"},
			Ecosystem:      models.EcosystemNPM,
		},
		{
			Name:           "typescript",
			Version:        "5.3.3",
			PackageManager: models.Bun,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
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

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseBunLock_NonStringFirstElement(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseBunLock("../fixtures/bun/non-string-spec.lock")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}
