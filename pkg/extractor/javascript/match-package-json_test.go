package javascript_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/testutility"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

var packageJSONMatcher = javascript.PackageJSONMatcher{}

func TestPackageJSONMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/does-not-exist/npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := packageJSONMatcher.GetSourceFile(lockFile)
	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestPackageJSONMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/package-json/one-package/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"package.json"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := packageJSONMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestPackageJSONMatcher_Match_OnePackage(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/one-package/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "lodash",
			PackageManager: models.NPM,
			TargetVersions: []string{"^4.0.0"},
			IsDirect:       true,
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_TransitiveDependencies(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/transitive/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "commander",
			PackageManager: models.NPM,
			TargetVersions: []string{"~2.0.0"},
			IsDirect:       true,
		},
		{
			Name:           "debug",
			TargetVersions: []string{"^0.7", "~0.7.2"},
			IsDirect:       true,
		},
		{
			Name:           "jear",
			TargetVersions: []string{"^0.1.4"},
			IsDirect:       true,
		},
		{
			Name:           "shelljs",
			TargetVersions: []string{"~0.1.4"},
			IsDirect:       true,
		},
		{
			Name:           "velocityjs",
			TargetVersions: []string{"~0.3.15"},
			IsDirect:       true,
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_NameConflict(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/name-conflict/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "aws-sdk-client-mock",
			PackageManager: models.NPM,
			TargetVersions: []string{"^2.1.1"},
			IsDirect:       true,
		},
		{
			Name:           "aws-sdk-client-mock-jest",
			TargetVersions: []string{"^2.1.1"},
			IsDirect:       true,
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_Resolutions(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/resolutions/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "fast-xml-parser",
			Version:        "4.2.5",
			PackageManager: models.NPM,
			TargetVersions: []string{"4.2.5"},
			IsDirect:       true,
		},
		{
			Name:           "fast-xml-parser",
			Version:        "4.4.0",
			TargetVersions: []string{"^4.2.5"},
			IsDirect:       true,
		},
		{
			Name:           "@aws-sdk/core",
			Version:        "3.535.0",
			TargetVersions: []string{"^3.535.0"},
			IsDirect:       true,
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_Target_Version(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/multiple-versions/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "foo",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.0.0 - 2.9999.9999"},
			IsDirect:       true,
		},
		{
			Name:           "bar",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">=1.0.2 <2.1.2"},
			IsDirect:       true,
		},
		{
			Name:           "baz",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">1.0.2 <=2.3.4"},
			IsDirect:       true,
		},
		{
			Name:           "boo",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.5.3"},
			IsDirect:       true,
		},
		{
			Name:           "qux",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"<1.0.0 || >=2.3.1 <2.4.5 || >=2.5.2 <3.0.0"},
			IsDirect:       true,
		},
		{
			Name:           "asd",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"http://asdf.com/asdf.tar.gz"},
			IsDirect:       true,
		},
		{
			Name:           "til",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"~1.5"},
			IsDirect:       true,
		},
		{
			Name:           "elf",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"~1.5.3"},
			IsDirect:       true,
		},
		{
			Name:           "two",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.x"},
			IsDirect:       true,
		},
		{
			Name:           "thr",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1.5.x"},
			IsDirect:       true,
		},
		{
			Name:           "lat",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"latest"},
			IsDirect:       true,
		},
		{
			Name:           "dyl",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"file:../dyl"},
			IsDirect:       true,
		},
		{
			Name:           "kpg",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"npm:pkg@1.5.0"},
			IsDirect:       true,
		},
		{
			Name:           "abc",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{"1"},
			IsDirect:       true,
		},
		{
			Name:           "cde",
			Version:        "1.5.3",
			PackageManager: models.NPM,
			TargetVersions: []string{">1.0.2"},
			IsDirect:       true,
		},
		{
			Name:           "dd",
			Version:        "0.0.0-use.local",
			PackageManager: models.NPM,
			TargetVersions: []string{"javascript/datadog"},
			IsDirect:       true,
		},
		{
			Name:           "dd2",
			Version:        "0.0.0-use.local",
			PackageManager: models.NPM,
			TargetVersions: []string{"javascript/datadog"},
			IsDirect:       true,
		},
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutility.NewSnapshot().MatchText(t, testutility.NormalizeJSON(t, packages))
}

func TestPackageJSONMatcher_Match_WorkspaceOrderIsDeterministic(t *testing.T) {
	t.Parallel()

	// "helper" is only reachable through the dev-only "tool" of workspace "a". It picks up the prod group of its
	// sibling "shared" (workspace "b") only if "b" is matched before "a", so the result depends on workspace order.
	tests := []struct {
		name string
		dir  string
	}{
		{name: "workspaces glob", dir: "workspaces-glob"},
		{name: "pnpm fallback", dir: "pnpm-fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for i := range 50 {
				sourceFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/workspace-order-dependent-dep-groups/" + tt.dir + "/package.json")
				if err != nil {
					t.Fatalf("Got unexpected error: %v", err)
				}

				packages := []extractor.PackageDetails{
					{Name: "tool", Version: "1.0.0", TargetVersions: []string{"^1.0.0"}, PackageManager: models.NPM, NameLocation: &models.FilePosition{Filename: "a"}},
					{Name: "shared", Version: "1.0.0", TargetVersions: []string{"^1.0.0"}, PackageManager: models.NPM, NameLocation: &models.FilePosition{Filename: "b"}},
					{Name: "helper", Version: "1.0.0", PackageManager: models.NPM},
				}
				packages[0].Dependencies = []*extractor.PackageDetails{&packages[1], &packages[2]}

				err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
				if err != nil {
					t.Fatalf("Got unexpected error: %v", err)
				}

				helper := packages[2]
				if !assert.Equal(t, []string{"dev"}, helper.DepGroups, "iteration %d", i) ||
					!assert.True(t, models.EcosystemNPM.IsDevGroup(helper.DepGroups), "iteration %d", i) {
					t.FailNow()
				}
			}
		})
	}
}
