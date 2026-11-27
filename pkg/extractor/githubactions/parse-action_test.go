package githubactions_test

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/githubactions"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
)

func TestActionExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "", want: false},
		{path: "action.yml", want: true},
		{path: "action.yaml", want: true},
		{path: ".github/actions/setup/action.yml", want: true},
		{path: "/abs/repo/nested/action.yaml", want: true},
		{path: "action.json", want: false},
		{path: "my-action.yml", want: false},
		{path: "action.yml/file", want: false},
		{path: ".github/workflows/ci.yml", want: false},
		{path: ".github/workflows/action.yml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			e := githubactions.ActionExtractor{}
			got := e.ShouldExtract(filepath.FromSlash(tt.path))
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) got = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseAction_Composite(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseAction(fixturesDir + "composite-action/action.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		pinnedAction("actions/setup-node", "60edb5dd545a775178f52524783378180af0d1f8"),
		action("aws-actions/configure-aws-credentials", "v4"),
	})

	// `    - uses: actions/setup-node@<sha> # v4.0.2`
	absPath := packages[0].BlockLocation.Filename
	if want := position(absPath, 6, 7, 72); packages[0].BlockLocation != want {
		t.Errorf("BlockLocation got = %+v, want %+v", packages[0].BlockLocation, want)
	}
	if want := positionPtr(absPath, 6, 32, 72); packages[0].VersionLocation == nil || *packages[0].VersionLocation != *want {
		t.Errorf("VersionLocation got = %+v, want %+v", packages[0].VersionLocation, want)
	}
}

func TestParseAction_CompositeYamlExtension(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseAction(fixturesDir + "composite-action-yaml/action.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/cache", "v4"),
	})
}

func TestParseAction_WithoutSteps(t *testing.T) {
	t.Parallel()

	tests := []string{
		// JavaScript actions run a script, they have no steps
		"javascript-action/action.yml",
		// Docker actions reference an image, which is not extracted
		"docker-action/action.yml",
		// A file named action.yml without a `runs` section is not an action
		"not-an-action/action.yml",
	}
	for _, fixture := range tests {
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()

			packages, err := githubactions.ParseAction(fixturesDir + fixture)
			if err != nil {
				t.Errorf("Got unexpected error: %v", err)
			}

			testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
		})
	}
}
