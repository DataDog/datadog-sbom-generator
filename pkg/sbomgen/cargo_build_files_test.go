package sbomgen

import (
	"encoding/json"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cargoTomlFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeCargoToml, FilePath: path}
}

func cargoTrees(t *testing.T, dir string) map[BuildFile]BuildFileRelations {
	t.Helper()

	sbom, err := GenerateSBOM([]string{dir}, DefaultOptions())
	require.NoError(t, err)

	return GetBuildFileTrees(sbom, FileTypeCargoToml)
}

func depPaths(rel BuildFileRelations) []string {
	paths := []string{}
	for _, dep := range rel.Dependencies {
		paths = append(paths, dep.FilePath)
	}

	return paths
}

func TestCargo_Single(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-single")
	root, ok := result[cargoTomlFile("Cargo.toml")]
	require.True(t, ok, "keys: %v", keys(result))
	assert.Equal(t, "single-app", root.ID)
	assert.Empty(t, root.Dependencies)
}

func TestCargo_VirtualWorkspace_Members(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-virtual")
	root, ok := result[cargoTomlFile("Cargo.toml")]
	require.True(t, ok, "keys: %v", keys(result))
	assert.Empty(t, root.ID)
	assert.Empty(t, root.Dependencies)

	for path, id := range map[string]string{
		"crates/core/Cargo.toml": "v-core",
		"crates/db/Cargo.toml":   "v-db",
		"crates/api/Cargo.toml":  "v-api",
	} {
		rel, ok := result[cargoTomlFile(path)]
		require.True(t, ok, "missing %s, keys: %v", path, keys(result))
		assert.Equal(t, id, rel.ID)
	}
	assert.NotContains(t, result, cargoTomlFile("crates/docs/Cargo.toml"))
}

func TestCargo_PathDependencySections(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-sections")
	app := result[cargoTomlFile("crates/app/Cargo.toml")]
	assert.Equal(t, []string{
		"crates/core/Cargo.toml",
		"crates/gen/Cargo.toml",
		"crates/renamed/Cargo.toml",
		"crates/unix/Cargo.toml",
	}, depPaths(app)) // testkit absent: dev-dependency; core listed once
	assert.Empty(t, result[cargoTomlFile("Cargo.toml")].Dependencies)
}

func TestCargo_WorkspaceInheritedDeps(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-virtual")
	assert.Equal(t, []string{"crates/core/Cargo.toml"}, depPaths(result[cargoTomlFile("crates/db/Cargo.toml")]))
	assert.Equal(t, []string{"crates/core/Cargo.toml", "crates/db/Cargo.toml"}, depPaths(result[cargoTomlFile("crates/api/Cargo.toml")]))
	assert.Empty(t, result[cargoTomlFile("Cargo.toml")].Dependencies)
}

func TestCargo_WorkspaceInheritedDepsUseOwnWorkspace(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-ws-collision")
	assert.Equal(t, []string{"b/b-util/Cargo.toml"}, depPaths(result[cargoTomlFile("b/x/Cargo.toml")]))
	assert.Equal(t, "c-b-util", result[cargoTomlFile("b/b-util/Cargo.toml")].ID)
}

func TestCargo_PackageRootDependsOnlyOnWhatItUses(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-pkg-ws")
	root := result[cargoTomlFile("Cargo.toml")]
	assert.Equal(t, "pw-root", root.ID)
	assert.Equal(t, []string{"lib/a/Cargo.toml"}, depPaths(root)) // no root→member edges
	assert.Contains(t, result, cargoTomlFile("lib/c/Cargo.toml"))
}

func TestCargo_ExcludedAndNonMemberCrates(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-exclude")
	assert.NotContains(t, result, cargoTomlFile("crates/legacy/Cargo.toml"))
	assert.Equal(t, []string{"crates/old/Cargo.toml", "vendor/vendored/Cargo.toml"}, depPaths(result[cargoTomlFile("crates/app/Cargo.toml")]))

	old := result[cargoTomlFile("crates/old/Cargo.toml")]
	assert.Equal(t, "x-old", old.ID)
	assert.Equal(t, []string{"vendor/vendored/Cargo.toml"}, depPaths(old))
	assert.Equal(t, "x-vendored", result[cargoTomlFile("vendor/vendored/Cargo.toml")].ID)
}

func TestCargo_PathOutsideScanRoot(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-outside-root/app")
	app := result[cargoTomlFile("Cargo.toml")]
	assert.Equal(t, "o-app", app.ID)
	assert.Empty(t, app.Dependencies)
	assert.Len(t, result, 1, "keys: %v", keys(result))
}

func TestCargo_NestedWorkspaceAndBrokenManifest(t *testing.T) {
	t.Parallel()

	sbom, err := GenerateSBOM([]string{"testdata/cargo-nested"}, DefaultOptions())
	require.NoError(t, err)
	result := GetBuildFileTrees(sbom, FileTypeCargoToml)

	fuzz := result[cargoTomlFile("fuzz/Cargo.toml")]
	assert.Equal(t, "n-fuzz", fuzz.ID)
	assert.Equal(t, []string{"crates/core/Cargo.toml"}, depPaths(fuzz))
	assert.Equal(t, "n-core", result[cargoTomlFile("crates/core/Cargo.toml")].ID)

	var bom cyclonedx.BOM
	require.NoError(t, json.Unmarshal(sbom, &bom))
	refs := map[string]int{}
	for _, c := range *bom.Components {
		if c.Type == cyclonedx.ComponentTypeFile {
			refs[c.BOMRef]++
		}
	}
	for ref, n := range refs {
		assert.Equal(t, 1, n, "duplicate component %s", ref)
	}
}

func TestCargo_MultipleScanDirsDoNotFail(t *testing.T) {
	t.Parallel()

	_, err := GenerateSBOM([]string{"testdata/cargo-single", "testdata/cargo-virtual"}, DefaultOptions())
	require.NoError(t, err)
}

func TestCargo_ShopExample(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-shop")
	want := map[string]struct {
		id   string
		deps []string
	}{
		"Cargo.toml":                 {"shop-api", []string{"crates/core/Cargo.toml", "crates/proto/Cargo.toml"}},
		"services/worker/Cargo.toml": {"shop-worker", []string{"crates/core/Cargo.toml", "crates/db/Cargo.toml"}},
		"crates/db/Cargo.toml":       {"shop-db", []string{"crates/core/Cargo.toml"}},
		"crates/core/Cargo.toml":     {"shop-core", []string{}},
		"crates/proto/Cargo.toml":    {"shop-proto", []string{}},
		"crates/testkit/Cargo.toml":  {"shop-testkit", []string{}},
		"tools/codegen/Cargo.toml":   {"shop-codegen", []string{}},
	}
	assert.Len(t, result, len(want), "keys: %v", keys(result))

	for path, w := range want {
		rel, ok := result[cargoTomlFile(path)]
		require.True(t, ok, "missing %s", path)
		assert.Equal(t, w.id, rel.ID, path)
		assert.Equal(t, w.deps, depPaths(rel), path)
	}
}

func TestCargo_FlagGating(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.ExtractArtifactIds = false
	sbom, err := GenerateSBOM([]string{"testdata/cargo-single"}, opts)
	require.NoError(t, err)

	for bf, rel := range GetBuildFileTrees(sbom, FileTypeCargoToml) {
		assert.Empty(t, rel.ID, bf.FilePath)
		assert.Empty(t, rel.Dependencies, bf.FilePath)
	}
}
