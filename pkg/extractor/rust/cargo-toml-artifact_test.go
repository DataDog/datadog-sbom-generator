package rust_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/rust"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check: CargoLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = rust.CargoLockExtractor{}

func TestCargoLockExtractor_GetArtifact_NameFromPackage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Write Cargo.lock (the file GetArtifact receives)
	cargoLockPath := filepath.Join(dir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	// Write sibling Cargo.toml with [package].name
	cargoTomlPath := filepath.Join(dir, "Cargo.toml")
	require.NoError(t, os.WriteFile(cargoTomlPath, []byte(`[package]
name = "my-crate"
version = "0.1.0"
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "my-crate", artifact.Name)
	assert.Equal(t, cargoLockPath, artifact.Filename)
	assert.Equal(t, models.EcosystemCratesIO, artifact.Ecosystem)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestCargoLockExtractor_GetArtifact_PathDep(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// main-crate/Cargo.lock + Cargo.toml
	mainDir := filepath.Join(root, "main-crate")
	require.NoError(t, os.MkdirAll(mainDir, 0755))

	cargoLockPath := filepath.Join(mainDir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	cargoTomlPath := filepath.Join(mainDir, "Cargo.toml")
	require.NoError(t, os.WriteFile(cargoTomlPath, []byte(`[package]
name = "main-crate"

[dependencies]
my-lib = { path = "../my-lib" }
serde = "1.0"
`), 0600))

	// Target my-lib/Cargo.toml must exist
	libDir := filepath.Join(root, "my-lib")
	require.NoError(t, os.MkdirAll(libDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "Cargo.toml"), []byte(`[package]
name = "my-lib"
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(libDir, "Cargo.toml"), artifact.ProjectDeps[0].Filename)
}

func TestCargoLockExtractor_GetArtifact_MissingCargoToml(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Only Cargo.lock, no sibling Cargo.toml
	cargoLockPath := filepath.Join(dir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, artifact, "missing Cargo.toml should return nil artifact")
}

func TestCargoLockExtractor_GetArtifact_NoPathDeps(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cargoLockPath := filepath.Join(dir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(`[package]
name = "my-crate"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestCargoLockExtractor_GetArtifact_MultiplePathDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	mainDir := filepath.Join(root, "main-crate")
	require.NoError(t, os.MkdirAll(mainDir, 0755))

	cargoLockPath := filepath.Join(mainDir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "Cargo.toml"), []byte(`[package]
name = "main-crate"

[dependencies]
lib-a = { path = "../lib-a" }

[dev-dependencies]
test-utils = { path = "../test-utils" }

[build-dependencies]
build-helper = { path = "../build-helper" }
`), 0600))

	// Create all three target crates
	for _, name := range []string{"lib-a", "test-utils", "build-helper"} {
		d := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(d, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(d, "Cargo.toml"), []byte(`[package]
name = "`+name+`"
`), 0600))
	}

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Len(t, artifact.ProjectDeps, 3, "should collect path deps from all three sections")
}

func TestCargoLockExtractor_GetArtifact_DeduplicatePathDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	mainDir := filepath.Join(root, "main-crate")
	require.NoError(t, os.MkdirAll(mainDir, 0755))

	cargoLockPath := filepath.Join(mainDir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	// Same path referenced in both [dependencies] and [dev-dependencies]
	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "Cargo.toml"), []byte(`[package]
name = "main-crate"

[dependencies]
shared = { path = "../shared" }

[dev-dependencies]
shared = { path = "../shared" }
`), 0600))

	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "Cargo.toml"), []byte(`[package]
name = "shared"
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Len(t, artifact.ProjectDeps, 1, "duplicate path deps should be deduplicated")
}

func TestCargoLockExtractor_GetArtifact_MissingTargetSkipped(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	mainDir := filepath.Join(root, "main-crate")
	require.NoError(t, os.MkdirAll(mainDir, 0755))

	cargoLockPath := filepath.Join(mainDir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "Cargo.toml"), []byte(`[package]
name = "main-crate"

[dependencies]
nonexistent = { path = "../nonexistent" }
`), 0600))

	// Do NOT create ../nonexistent/Cargo.toml

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "missing target Cargo.toml should be silently skipped")
}

func TestCargoLockExtractor_GetArtifact_OutsideScanRootSkipped(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()

	scanRoot := filepath.Join(repo, "scanRoot")
	mainDir := filepath.Join(scanRoot, "main-crate")
	require.NoError(t, os.MkdirAll(mainDir, 0755))

	cargoLockPath := filepath.Join(mainDir, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "Cargo.toml"), []byte(`[package]
name = "main-crate"

[dependencies]
outside = { path = "../../outside" }
`), 0600))

	// outside/ exists but is outside scanRoot
	outsideDir := filepath.Join(repo, "outside")
	require.NoError(t, os.MkdirAll(outsideDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "Cargo.toml"), []byte(`[package]
name = "outside"
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	ctx := extractor.ScanContext{RootDir: scanRoot}
	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, ctx)
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "path dep outside scan root must be skipped")
}
