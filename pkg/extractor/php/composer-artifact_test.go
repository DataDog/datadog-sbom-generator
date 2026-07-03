package php_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/php"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check: ComposerLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = php.ComposerLockExtractor{}

func TestComposerLockExtractor_GetArtifact_NameFromComposerJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "composer.lock")
	err := os.WriteFile(lockfilePath, []byte(`{"packages": []}`), 0600)
	require.NoError(t, err)

	composerJSONPath := filepath.Join(dir, "composer.json")
	err = os.WriteFile(composerJSONPath, []byte(`{"name": "vendor/project"}`), 0600)
	require.NoError(t, err)

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := php.ComposerExtractor.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "vendor/project", artifact.Name)
	assert.Equal(t, lockfilePath, artifact.Filename)
	assert.Equal(t, models.EcosystemPackagist, artifact.Ecosystem)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestComposerLockExtractor_GetArtifact_MissingComposerJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "composer.lock")
	err := os.WriteFile(lockfilePath, []byte(`{"packages": []}`), 0600)
	require.NoError(t, err)

	// No composer.json in the directory

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := php.ComposerExtractor.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Empty(t, artifact.Name)
	assert.Equal(t, lockfilePath, artifact.Filename)
	assert.Equal(t, models.EcosystemPackagist, artifact.Ecosystem)
}

func TestComposerLockExtractor_GetArtifact_NoNameField(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "composer.lock")
	err := os.WriteFile(lockfilePath, []byte(`{"packages": []}`), 0600)
	require.NoError(t, err)

	composerJSONPath := filepath.Join(dir, "composer.json")
	err = os.WriteFile(composerJSONPath, []byte(`{"require": {"php": "^8.1"}}`), 0600)
	require.NoError(t, err)

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := php.ComposerExtractor.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Empty(t, artifact.Name)
	assert.Equal(t, lockfilePath, artifact.Filename)
	assert.Equal(t, models.EcosystemPackagist, artifact.Ecosystem)
}
