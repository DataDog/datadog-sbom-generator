package lockfile_test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestParsePnpmLock_v9_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/no-packages.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePnpmLock_v9_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

func TestParsePnpmLock_v9_OnePackageDev(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/one-package-dev.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/scoped-packages.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/peer-dependencies-advanced.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/multiple-versions.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/commits.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

func TestParsePnpmLock_v9_MixedGroups(t *testing.T) {
	t.Parallel()

	packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/mixed-groups.v9.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
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

// TestParsePnpmLock_v9_WorkspaceDevConsistency demonstrates the non-deterministic
// behavior in workspace dev dependency detection
func TestParsePnpmLock_v9_WorkspaceDevConsistency(t *testing.T) {
	t.Parallel()

	// Run the parser multiple times to check for non-deterministic behavior
	const iterations = 100

	// Create a map of package name@version -> isDevGroup result for all iterations
	currentResults := make(map[string][]string)

	for i := 0; i < iterations; i++ {
		// this fixture file is coming from https://github.com/vuejs/core. Which is a complex pnpm lock file
		packages, err := lockfile.ParsePnpmLock("fixtures/pnpm/is-dev-inconsistency.v9.yaml")
		if err != nil {
			t.Errorf("Got unexpected error: %v", err)
		}

		for _, pkg := range packages {
			packageKey := pkg.Name + "@" + pkg.Version
			isDevResult := models.EcosystemNPM.IsDevGroup(pkg.DepGroups)
			currentResults[packageKey] = append(currentResults[packageKey], strconv.FormatBool(isDevResult))
		}
	}

	var keysWithMultipleUnique []string

	for key, values := range currentResults {
		uniq := make(map[string]struct{})
		for _, v := range values {
			uniq[v] = struct{}{}
		}

		if len(uniq) > 1 {
			keysWithMultipleUnique = append(keysWithMultipleUnique, key)
		}
	}

	if len(keysWithMultipleUnique) > 0 {
		assert.Empty(t, keysWithMultipleUnique)
		fmt.Printf("We found multiple is-dev values for the same package:%v ", keysWithMultipleUnique)
	}
}
