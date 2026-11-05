package sbomgen

import (
	"testing"

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

func TestCargo_Single(t *testing.T) {
	t.Parallel()

	result := cargoTrees(t, "testdata/cargo-single")
	root, ok := result[cargoTomlFile("Cargo.toml")]
	require.True(t, ok, "keys: %v", keys(result))
	assert.Equal(t, "single-app", root.ID)
	assert.Empty(t, root.Dependencies)
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
