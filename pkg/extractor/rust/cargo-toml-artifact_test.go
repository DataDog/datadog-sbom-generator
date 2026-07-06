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
	assert.Equal(t, cargoTomlPath, artifact.Filename)
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

func TestGetArtifact_WorkspaceVirtualManifest(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Cargo.lock at workspace root
	cargoLockPath := filepath.Join(root, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	// Virtual manifest: no [package], only [workspace]
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`[workspace]
members = ["crate-a", "crate-b"]
`), 0600))

	// Create member crates
	for _, name := range []string{"crate-a", "crate-b"} {
		d := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(d, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(d, "Cargo.toml"), []byte(`[package]
name = "`+name+`"
version = "0.1.0"
`), 0600))
	}

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	// Virtual manifest has no package name
	assert.Equal(t, "", artifact.Name)
	assert.Equal(t, filepath.Join(root, "Cargo.toml"), artifact.Filename)

	// Should discover both members as satellites
	require.Len(t, artifact.Satellites, 2)

	satelliteNames := make(map[string]string)
	for _, sat := range artifact.Satellites {
		satelliteNames[sat.Name] = sat.Filename
	}
	assert.Contains(t, satelliteNames, "crate-a")
	assert.Contains(t, satelliteNames, "crate-b")
	assert.Equal(t, filepath.Join(root, "crate-a", "Cargo.toml"), satelliteNames["crate-a"])
	assert.Equal(t, filepath.Join(root, "crate-b", "Cargo.toml"), satelliteNames["crate-b"])
}

func TestGetArtifact_WorkspaceWithCrossDepsBetweenMembers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	cargoLockPath := filepath.Join(root, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`[workspace]
members = ["crate-a", "crate-b"]
`), 0600))

	// crate-a has no path deps
	crateADir := filepath.Join(root, "crate-a")
	require.NoError(t, os.MkdirAll(crateADir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(crateADir, "Cargo.toml"), []byte(`[package]
name = "crate-a"
version = "0.1.0"
`), 0600))

	// crate-b depends on crate-a via path
	crateBDir := filepath.Join(root, "crate-b")
	require.NoError(t, os.MkdirAll(crateBDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(crateBDir, "Cargo.toml"), []byte(`[package]
name = "crate-b"
version = "0.1.0"

[dependencies]
crate-a = { path = "../crate-a" }
`), 0600))

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.Satellites, 2)

	// Find the crate-b satellite and check its ProjectDeps
	var crateBSatellite *models.ScannedArtifact
	for _, sat := range artifact.Satellites {
		if sat.Name == "crate-b" {
			crateBSatellite = sat

			break
		}
	}
	require.NotNil(t, crateBSatellite, "crate-b satellite must exist")
	require.Len(t, crateBSatellite.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(crateADir, "Cargo.toml"), crateBSatellite.ProjectDeps[0].Filename)
}

func TestGetArtifact_WorkspaceGlobPattern(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	cargoLockPath := filepath.Join(root, "Cargo.lock")
	require.NoError(t, os.WriteFile(cargoLockPath, []byte("version = 3\n"), 0600))

	// Workspace with glob pattern
	require.NoError(t, os.WriteFile(filepath.Join(root, "Cargo.toml"), []byte(`[workspace]
members = ["crates/*"]
`), 0600))

	// Create crates directory with two members
	cratesDir := filepath.Join(root, "crates")
	require.NoError(t, os.MkdirAll(cratesDir, 0755))

	for _, name := range []string{"foo", "bar"} {
		d := filepath.Join(cratesDir, name)
		require.NoError(t, os.MkdirAll(d, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(d, "Cargo.toml"), []byte(`[package]
name = "`+name+`"
version = "0.1.0"
`), 0600))
	}

	f, err := extractor.OpenLocalDepFile(cargoLockPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := rust.CargoLockExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	require.Len(t, artifact.Satellites, 2)

	satelliteNames := make(map[string]bool)
	for _, sat := range artifact.Satellites {
		satelliteNames[sat.Name] = true
	}
	assert.True(t, satelliteNames["foo"], "glob should discover foo")
	assert.True(t, satelliteNames["bar"], "glob should discover bar")
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
