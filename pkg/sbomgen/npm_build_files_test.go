package sbomgen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNpmWorkspace_BuildFileTrees is an end-to-end integration test that
// verifies the full pipeline: GenerateSBOM -> GetBuildFileTrees for an npm
// workspace monorepo with two workspace packages.
func TestNpmWorkspace_BuildFileTrees(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	sbom, err := GenerateSBOM([]string{"testdata/npm-workspace"}, opts)
	require.NoError(t, err)
	require.NotEmpty(t, sbom)

	result := GetBuildFileTrees(sbom, FileTypePackageJSON)

	// Expect at least the root package.json. Workspace package.json files
	// should also appear if the root has dependency edges to them.
	rootKey := packageJSONFile("package.json")
	root, ok := result[rootKey]
	require.True(t, ok, "expected root package.json in build file trees, got keys: %v", keys(result))

	// Root should have an ID derived from the npm purl. The purl library
	// encodes the full scoped name as the purl name (no namespace split for
	// npm), so parseArtifactID returns the name as-is.
	assert.Equal(t, "@test/root", root.ID)

	// Root should depend on workspace package.json files
	require.Len(t, root.Dependencies, 2, "expected 2 workspace dependencies")

	depPaths := make([]string, len(root.Dependencies))
	for i, dep := range root.Dependencies {
		depPaths[i] = dep.BuildFile.FilePath
	}

	assert.Contains(t, depPaths, "packages/core/package.json")
	assert.Contains(t, depPaths, "packages/utils/package.json")

	// Workspace package.json files should be present with no further dependencies
	coreKey := packageJSONFile("packages/core/package.json")
	core, ok := result[coreKey]
	require.True(t, ok, "expected packages/core/package.json in results")
	assert.Empty(t, core.Dependencies)

	utilsKey := packageJSONFile("packages/utils/package.json")
	utils, ok := result[utilsKey]
	require.True(t, ok, "expected packages/utils/package.json in results")
	assert.Empty(t, utils.Dependencies)
}

// TestNpmWorkspace_BuildFileTrees_FlagGating verifies that with
// ExtractArtifactIds disabled, no package.json file-type components appear.
func TestNpmWorkspace_BuildFileTrees_FlagGating(t *testing.T) {
	t.Parallel()

	opts := DefaultOptions()
	opts.ExtractArtifactIds = false
	sbom, err := GenerateSBOM([]string{"testdata/npm-workspace"}, opts)
	require.NoError(t, err)
	require.NotEmpty(t, sbom)

	result := GetBuildFileTrees(sbom, FileTypePackageJSON)

	// With artifact extraction disabled, no file-type components are created,
	// so GetBuildFileTrees should return nothing for package.json.
	// However, manifest occurrences may still be present if ManifestParsers
	// is enabled; we only check that no file-type build-file-tree relations
	// with dependency edges are returned.
	for bf, rel := range result {
		assert.Empty(t, rel.Dependencies,
			"expected no dependencies for %s with ExtractArtifactIds=false", bf.FilePath)
		assert.Empty(t, rel.ID,
			"expected no ID for %s with ExtractArtifactIds=false", bf.FilePath)
	}
}

// keys extracts map keys for diagnostic output.
func keys(m map[BuildFile]BuildFileRelations) []BuildFile {
	result := make([]BuildFile, 0, len(m))
	for k := range m {
		result = append(result, k)
	}

	return result
}
