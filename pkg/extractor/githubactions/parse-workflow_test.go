package githubactions_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/githubactions"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const fixturesDir = "../fixtures/github-actions/"

func action(name, version string) extractor.PackageDetails {
	return extractor.PackageDetails{
		Name:           name,
		Version:        version,
		PackageManager: models.GitHubActions,
		Ecosystem:      models.EcosystemGitHubActions,
		IsDirect:       true,
	}
}

func pinnedAction(name, sha string) extractor.PackageDetails {
	pkg := action(name, sha)
	pkg.Commit = sha

	return pkg
}

func position(path string, line, columnStart, columnEnd int) models.FilePosition {
	return models.FilePosition{
		Line:     models.Position{Start: line, End: line},
		Column:   models.Position{Start: columnStart, End: columnEnd},
		Filename: path,
	}
}

func positionPtr(path string, line, columnStart, columnEnd int) *models.FilePosition {
	pos := position(path, line, columnStart, columnEnd)

	return &pos
}

func TestWorkflowExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "", want: false},
		{path: ".github/workflows/ci.yml", want: true},
		{path: ".github/workflows/ci.yaml", want: true},
		{path: "path/to/repo/.github/workflows/release.yml", want: true},
		{path: "/abs/repo/.github/workflow-templates/ci.yml", want: true},
		{path: ".github/workflows/ci.json", want: false},
		{path: ".github/workflows/nested/ci.yml", want: false},
		{path: ".github/ci.yml", want: false},
		{path: "workflows/ci.yml", want: false},
		{path: "github/workflows/ci.yml", want: false},
		{path: ".gitea/workflows/ci.yml", want: false},
		{path: ".github/workflow-templates/ci.properties.json", want: false},
		{path: ".github/dependabot.yml", want: false},
		{path: "action.yml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			e := githubactions.WorkflowExtractor{}
			got := e.ShouldExtract(filepath.FromSlash(tt.path))
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) got = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseWorkflow_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "does-not-exist/.github/workflows/ci.yml")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseWorkflow_InvalidYaml(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "invalid-yaml/.github/workflows/ci.yml")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseWorkflow_Empty(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "empty/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseWorkflow_NoJobs(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "no-jobs/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseWorkflow_AllForms(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "all-forms/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Local actions and workflows (./...), docker images (docker://...), container and service images
	// are not extracted.
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4.1.1"),
		pinnedAction("actions/setup-go", "0c52d547c9bc32b1aa3301fd7a9cb496313a4491"),
		action("github/codeql-action", "v3"),
		action("actions/cache", "v4"),
		action("docker/build-push-action", "main"),
		action("octo-org/shared", "v2"),
	})

	// Each occurrence of an action is reported: actions/checkout is used twice.
	if len(packages) != 7 {
		t.Errorf("Expected 7 packages, got %d", len(packages))
	}
	if packages[0].BlockLocation.Line.Start != 11 || packages[5].BlockLocation.Line.Start != 20 {
		t.Errorf("Expected actions/checkout at lines 11 and 20, got %d and %d", packages[0].BlockLocation.Line.Start, packages[5].BlockLocation.Line.Start)
	}
}

func TestParseWorkflow_AllForms_Locations(t *testing.T) {
	t.Parallel()

	path := fixturesDir + "all-forms/.github/workflows/ci.yml"
	packages, err := githubactions.ParseWorkflow(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	if len(packages) != 7 {
		t.Fatalf("Expected 7 packages, got %d", len(packages))
	}
	absPath := packages[0].BlockLocation.Filename

	tests := []struct {
		name     string
		pkg      extractor.PackageDetails
		block    models.FilePosition
		nameLoc  *models.FilePosition
		version  *models.FilePosition
		position int
	}{
		{
			// `      - uses: actions/checkout@v4.1.1`
			name:     "plain value",
			position: 0,
			block:    position(absPath, 11, 9, 38),
			nameLoc:  positionPtr(absPath, 11, 15, 31),
			version:  positionPtr(absPath, 11, 32, 38),
		},
		{
			// `        uses: actions/setup-go@<sha> # v5.0.0`: the comment is not part of the block
			name:     "pinned value with a comment",
			position: 1,
			block:    position(absPath, 13, 9, 72),
			nameLoc:  positionPtr(absPath, 13, 15, 31),
			version:  positionPtr(absPath, 13, 32, 72),
		},
		{
			// `      - uses: github/codeql-action/init@v3`: the sub path is not part of the name
			name:     "sub path",
			position: 2,
			block:    position(absPath, 14, 9, 43),
			nameLoc:  positionPtr(absPath, 14, 15, 35),
			version:  positionPtr(absPath, 14, 41, 43),
		},
		{
			// `      - uses: "actions/cache@v4"`: quotes are part of the block only
			name:     "double quoted value",
			position: 3,
			block:    position(absPath, 15, 9, 33),
			nameLoc:  positionPtr(absPath, 15, 16, 29),
			version:  positionPtr(absPath, 15, 30, 32),
		},
		{
			// `    uses: octo-org/shared/.github/workflows/build.yml@v2`
			name:     "reusable workflow",
			position: 6,
			block:    position(absPath, 22, 5, 57),
			nameLoc:  positionPtr(absPath, 22, 11, 26),
			version:  positionPtr(absPath, 22, 55, 57),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkg := packages[tt.position]
			if pkg.LocationRole != models.LocationRoleManifest {
				t.Errorf("LocationRole got = %q, want %q", pkg.LocationRole, models.LocationRoleManifest)
			}
			if pkg.BlockLocation != tt.block {
				t.Errorf("BlockLocation got = %+v, want %+v", pkg.BlockLocation, tt.block)
			}
			if pkg.NameLocation == nil || *pkg.NameLocation != *tt.nameLoc {
				t.Errorf("NameLocation got = %+v, want %+v", pkg.NameLocation, tt.nameLoc)
			}
			if pkg.VersionLocation == nil || *pkg.VersionLocation != *tt.version {
				t.Errorf("VersionLocation got = %+v, want %+v", pkg.VersionLocation, tt.version)
			}
		})
	}
}

func TestParseWorkflow_Anchors(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "anchors/.github/workflows/ci.yaml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// The aliased step is the anchored declaration: it is reported once, at the anchor.
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4"),
		action("actions/setup-node", "v4"),
	})
	if packages[0].BlockLocation.Line.Start != 6 {
		t.Errorf("Expected the aliased step to be located at its anchor (line 6), got line %d", packages[0].BlockLocation.Line.Start)
	}
}

func TestParseWorkflow_ScalarAnchors(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "scalar-anchors/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// `uses: *checkout` refers to a value anchored elsewhere: it is reported once, at the anchor.
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4"),
		action("actions/setup-go", "v5"),
	})

	// `  "✅": &checkout actions/checkout@v4`: the block is the anchored value, columns are in bytes.
	absPath := packages[0].BlockLocation.Filename
	if want := position(absPath, 3, 20, 39); packages[0].BlockLocation != want {
		t.Errorf("BlockLocation got = %+v, want %+v", packages[0].BlockLocation, want)
	}
	if want := positionPtr(absPath, 3, 20, 36); packages[0].NameLocation == nil || *packages[0].NameLocation != *want {
		t.Errorf("NameLocation got = %+v, want %+v", packages[0].NameLocation, want)
	}
	if want := positionPtr(absPath, 3, 37, 39); packages[0].VersionLocation == nil || *packages[0].VersionLocation != *want {
		t.Errorf("VersionLocation got = %+v, want %+v", packages[0].VersionLocation, want)
	}
}

func TestParseWorkflow_FlowStyle(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "flow-style/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4"),
	})

	// The line holds a multi-byte emoji before the `uses:` key: columns are reported in bytes.
	absPath := packages[0].BlockLocation.Filename
	if want := position(absPath, 4, 38, 63); packages[0].BlockLocation != want {
		t.Errorf("BlockLocation got = %+v, want %+v", packages[0].BlockLocation, want)
	}
	if want := positionPtr(absPath, 4, 44, 60); packages[0].NameLocation == nil || *packages[0].NameLocation != *want {
		t.Errorf("NameLocation got = %+v, want %+v", packages[0].NameLocation, want)
	}
}

func TestParseWorkflow_CRLF(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "crlf/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4"),
	})
	absPath := packages[0].BlockLocation.Filename
	if want := position(absPath, 5, 9, 34); packages[0].BlockLocation != want {
		t.Errorf("BlockLocation got = %+v, want %+v", packages[0].BlockLocation, want)
	}
}

func TestParseWorkflow_MalformedUses(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "malformed-uses/.github/workflows/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Values GitHub cannot resolve are skipped, the rest of the file is still extracted.
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/setup-python", "v5"),
	})
}

func TestParseWorkflow_WorkflowTemplates(t *testing.T) {
	t.Parallel()

	packages, err := githubactions.ParseWorkflow(fixturesDir + "workflow-templates/.github/workflow-templates/ci.yml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		action("actions/checkout", "v4"),
	})
}
