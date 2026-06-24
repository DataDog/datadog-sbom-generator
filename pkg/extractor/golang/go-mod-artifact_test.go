package golang_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/golang"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check: GoLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = golang.GoLockExtractor{}

func TestGoLockExtractor_GetArtifact_NameFromModuleDirective(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21
`), 0600)
	require.NoError(t, err)

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "github.com/mycompany/svcA", artifact.Name)
	assert.Equal(t, goModPath, artifact.Filename)
	assert.Equal(t, models.EcosystemGo, artifact.Ecosystem)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestGoLockExtractor_GetArtifact_LocalReplace(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// svcA/go.mod with a local replace pointing to ../shared
	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/shared v0.0.0

replace github.com/mycompany/shared => ../shared
`), 0600)
	require.NoError(t, err)

	// shared/go.mod must exist for the dep to be emitted
	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	sharedGoMod := filepath.Join(sharedDir, "go.mod")
	require.NoError(t, os.WriteFile(sharedGoMod, []byte(`module github.com/mycompany/shared

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, sharedGoMod, artifact.ProjectDeps[0].Filename)
	assert.Empty(t, artifact.ProjectDeps[0].Name, "ProjectDeps should carry only Filename, not Name")
}

func TestGoLockExtractor_GetArtifact_MissingTargetSkipped(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/shared v0.0.0

replace github.com/mycompany/shared => ../shared
`), 0600)
	require.NoError(t, err)

	// shared/ directory does NOT have a go.mod

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "missing target go.mod should be silently skipped")
}

func TestGoLockExtractor_GetArtifact_Deduplication(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	// Two replace directives pointing to the same directory
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require (
	github.com/mycompany/foo v0.0.0
	github.com/mycompany/bar v0.0.0
)

replace (
	github.com/mycompany/foo => ../shared
	github.com/mycompany/bar => ../shared
)
`), 0600)
	require.NoError(t, err)

	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "go.mod"), []byte(`module github.com/mycompany/shared

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Len(t, artifact.ProjectDeps, 1, "duplicate replace targets should be deduplicated")
}

func TestGoLockExtractor_GetArtifact_AbsoluteLocalReplace(t *testing.T) {
	t.Parallel()

	// A replace directive with an absolute path on the right-hand side (no
	// version) is a valid local directory reference that must not be joined
	// with goModDir. filepath.Join(goModDir, "/abs/path") produces a wrong
	// path on some platforms; we must use the absolute path directly.
	root := t.TempDir()

	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")

	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	sharedGoMod := filepath.Join(sharedDir, "go.mod")
	require.NoError(t, os.WriteFile(sharedGoMod, []byte(`module github.com/mycompany/shared

go 1.21
`), 0600))

	// Write go.mod with an absolute path replace (using the temp dir path).
	err := os.WriteFile(goModPath, []byte("module github.com/mycompany/svcA\n\ngo 1.21\n\nrequire github.com/mycompany/shared v0.0.0\n\nreplace github.com/mycompany/shared => "+sharedDir+"\n"), 0600)
	require.NoError(t, err)

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.Len(t, artifact.ProjectDeps, 1, "absolute replace path must be used directly, not joined with module dir")
	assert.Equal(t, sharedGoMod, artifact.ProjectDeps[0].Filename)
}

func TestGoLockExtractor_GetArtifact_RemoteReplaceIgnored(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	goModPath := filepath.Join(dir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/foo v1.0.0

replace github.com/mycompany/foo => github.com/other/bar v1.0.0
`), 0600)
	require.NoError(t, err)

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "remote replace should not produce ProjectDeps")
}

func TestGoLockExtractor_GetArtifact_RelativeRootDir(t *testing.T) {
	t.Parallel()

	// Verify that a relative ctx.RootDir (e.g. ".") is normalised to an
	// absolute path before the containment check. filepath.Rel(".", "/abs/…")
	// returns an error, which must NOT cause valid replace edges to be dropped.
	root := t.TempDir()

	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/shared v0.0.0

replace github.com/mycompany/shared => ../shared
`), 0600)
	require.NoError(t, err)

	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	sharedGoMod := filepath.Join(sharedDir, "go.mod")
	require.NoError(t, os.WriteFile(sharedGoMod, []byte(`module github.com/mycompany/shared

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	// Pass a relative RootDir — must not cause valid edges to be silently dropped.
	ctx := extractor.ScanContext{RootDir: root}
	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, ctx)
	require.NoError(t, err)
	require.Len(t, artifact.ProjectDeps, 1, "replace target inside scan root must be included even with relative RootDir")
	assert.Equal(t, sharedGoMod, artifact.ProjectDeps[0].Filename)
}

func TestGoLockExtractor_GetArtifact_OutsideScanRootSkipped(t *testing.T) {
	t.Parallel()

	// repo/
	//   scanRoot/
	//     svcA/go.mod  ← scan root is scanRoot/, not repo/
	//   shared/go.mod  ← outside scan root
	//
	// svcA replaces github.com/mycompany/shared => ../../shared
	// The target exists on disk but is outside ctx.RootDir, so it must be skipped.
	repo := t.TempDir()

	scanRoot := filepath.Join(repo, "scanRoot")
	svcADir := filepath.Join(scanRoot, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/shared v0.0.0

replace github.com/mycompany/shared => ../../shared
`), 0600)
	require.NoError(t, err)

	sharedDir := filepath.Join(repo, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "go.mod"), []byte(`module github.com/mycompany/shared

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	ctx := extractor.ScanContext{RootDir: scanRoot}
	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, ctx)
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "replace target outside scan root must be skipped")
}

func TestGoLockExtractor_GetArtifact_VersionedReplaceIgnored(t *testing.T) {
	t.Parallel()

	// A versioned right-hand side (replace old => new v1.2.3) is always a
	// remote module path per the Go spec, never a local directory — even if
	// the path does not look like a hostname.  Verify it produces no ProjectDep.
	root := t.TempDir()
	svcADir := filepath.Join(root, "svcA")
	require.NoError(t, os.MkdirAll(svcADir, 0755))
	goModPath := filepath.Join(svcADir, "go.mod")
	err := os.WriteFile(goModPath, []byte(`module github.com/mycompany/svcA

go 1.21

require github.com/mycompany/foo v1.0.0

replace github.com/mycompany/foo => my-internal-fork v1.0.0
`), 0600)
	require.NoError(t, err)

	// Even if a directory named "my-internal-fork/go.mod" exists, it must be ignored.
	forkDir := filepath.Join(root, "svcA", "my-internal-fork")
	require.NoError(t, os.MkdirAll(forkDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(forkDir, "go.mod"), []byte(`module my-internal-fork

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(goModPath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "versioned replace should not produce ProjectDeps")
}

func TestGoLockExtractor_GetArtifact_DirectDepsOnly(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// a/go.mod replaces => ../b
	aDir := filepath.Join(root, "a")
	require.NoError(t, os.MkdirAll(aDir, 0755))
	err := os.WriteFile(filepath.Join(aDir, "go.mod"), []byte(`module github.com/mycompany/a

go 1.21

require github.com/mycompany/b v0.0.0

replace github.com/mycompany/b => ../b
`), 0600)
	require.NoError(t, err)

	// b/go.mod replaces => ../c
	bDir := filepath.Join(root, "b")
	require.NoError(t, os.MkdirAll(bDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(bDir, "go.mod"), []byte(`module github.com/mycompany/b

go 1.21

require github.com/mycompany/c v0.0.0

replace github.com/mycompany/c => ../c
`), 0600))

	// c/go.mod
	cDir := filepath.Join(root, "c")
	require.NoError(t, os.MkdirAll(cDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(cDir, "go.mod"), []byte(`module github.com/mycompany/c

go 1.21
`), 0600))

	f, err := extractor.OpenLocalDepFile(filepath.Join(aDir, "go.mod"))
	require.NoError(t, err)
	defer f.Close()

	artifact, err := golang.GoLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	// Only b/go.mod should appear — c/go.mod is transitive (handled by SimpleProcessor BFS)
	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(bDir, "go.mod"), artifact.ProjectDeps[0].Filename)
}
