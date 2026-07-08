package javascript_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check: YarnLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = javascript.YarnLockExtractor{}

func TestYarnLockExtractor_GetArtifact_WorkspaceMonorepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "@test/root",
  "workspaces": ["packages/*"]
}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0600)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "core"), 0755))
	err = os.WriteFile(filepath.Join(root, "packages", "core", "package.json"), []byte(`{
  "name": "@test/core"
}`), 0600)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "utils"), 0755))
	err = os.WriteFile(filepath.Join(root, "packages", "utils", "package.json"), []byte(`{
  "name": "@test/utils"
}`), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "yarn.lock")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.YarnLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "@test/root", artifact.Name)
	assert.Equal(t, filepath.Join(root, "package.json"), artifact.Filename)
	assert.Equal(t, models.EcosystemNPM, artifact.Ecosystem)

	require.Len(t, artifact.ProjectDeps, 2)
	assert.Equal(t, filepath.Join(root, "packages", "core", "package.json"), artifact.ProjectDeps[0].Filename)
	assert.Equal(t, filepath.Join(root, "packages", "utils", "package.json"), artifact.ProjectDeps[1].Filename)
}

func TestYarnLockExtractor_GetArtifact_SinglePackage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "my-single-pkg"
}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "yarn.lock")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.YarnLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "my-single-pkg", artifact.Name)
	assert.Equal(t, filepath.Join(root, "package.json"), artifact.Filename)
	assert.Equal(t, models.EcosystemNPM, artifact.Ecosystem)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestYarnLockExtractor_GetArtifact_MissingPackageJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "yarn.lock"), []byte("# yarn lockfile v1\n"), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "yarn.lock")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.YarnLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, artifact)
}
