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

// Compile-time check: PnpmLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = javascript.PnpmLockExtractor{}

func TestPnpmLockExtractor_GetArtifact_WorkspaceMonorepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name": "@test/root"}`), 0600)
	require.NoError(t, err)

	// pnpm-lock.yaml with importers — the source of truth for pnpm workspaces.
	err = os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies: {}
  packages/core:
    dependencies: {}
  packages/utils:
    dependencies: {}
`), 0600)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "core"), 0755))
	err = os.WriteFile(filepath.Join(root, "packages", "core", "package.json"), []byte(`{"name": "@test/core"}`), 0600)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "packages", "utils"), 0755))
	err = os.WriteFile(filepath.Join(root, "packages", "utils", "package.json"), []byte(`{"name": "@test/utils"}`), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "pnpm-lock.yaml")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.PnpmLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "@test/root", artifact.Name)
	assert.Equal(t, filepath.Join(root, "package.json"), artifact.Filename)
	assert.Equal(t, models.EcosystemNPM, artifact.Ecosystem)

	// Collect deps for order-independent comparison.
	depFiles := make([]string, len(artifact.ProjectDeps))
	for i, dep := range artifact.ProjectDeps {
		depFiles[i] = dep.Filename
	}

	require.Len(t, depFiles, 2)
	assert.Contains(t, depFiles, filepath.Join(root, "packages", "core", "package.json"))
	assert.Contains(t, depFiles, filepath.Join(root, "packages", "utils", "package.json"))
}

// TestPnpmLockExtractor_GetArtifact_PnpmWorkspaceYaml verifies that workspaces
// declared only via pnpm-workspace.yaml (no workspaces field in package.json)
// are still discovered via the pnpm-lock.yaml importers map.
func TestPnpmLockExtractor_GetArtifact_PnpmWorkspaceYaml(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// package.json has NO workspaces field — pnpm-workspace.yaml is the declaration.
	err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name": "my-pnpm-app"}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies: {}
  apps/web:
    dependencies: {}
`), 0600)
	require.NoError(t, err)

	require.NoError(t, os.MkdirAll(filepath.Join(root, "apps", "web"), 0755))
	err = os.WriteFile(filepath.Join(root, "apps", "web", "package.json"), []byte(`{"name": "web"}`), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "pnpm-lock.yaml")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.PnpmLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "my-pnpm-app", artifact.Name)
	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(root, "apps", "web", "package.json"), artifact.ProjectDeps[0].Filename)
}

func TestPnpmLockExtractor_GetArtifact_SinglePackage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{
  "name": "my-single-pkg"
}`), 0600)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "pnpm-lock.yaml")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.PnpmLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "my-single-pkg", artifact.Name)
	assert.Equal(t, filepath.Join(root, "package.json"), artifact.Filename)
	assert.Equal(t, models.EcosystemNPM, artifact.Ecosystem)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestPnpmLockExtractor_GetArtifact_MissingPackageJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	err := os.WriteFile(filepath.Join(root, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0600)
	require.NoError(t, err)

	lockfilePath := filepath.Join(root, "pnpm-lock.yaml")
	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := javascript.PnpmLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, artifact)
}
