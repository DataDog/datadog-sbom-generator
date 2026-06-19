package java_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBazelBuildExtractor_ShouldExtract_BUILD_bazel(t *testing.T) {
	t.Parallel()

	assert.True(t, java.BazelBuildExtractor{}.ShouldExtract("path/to/BUILD.bazel"))
}

func TestBazelBuildExtractor_ShouldExtract_BUILD(t *testing.T) {
	t.Parallel()

	assert.True(t, java.BazelBuildExtractor{}.ShouldExtract("path/to/BUILD"))
}

func TestBazelBuildExtractor_ShouldExtract_other(t *testing.T) {
	t.Parallel()

	assert.False(t, java.BazelBuildExtractor{}.ShouldExtract("path/to/pom.xml"))
	assert.False(t, java.BazelBuildExtractor{}.ShouldExtract("path/to/build.gradle"))
	assert.False(t, java.BazelBuildExtractor{}.ShouldExtract("path/to/BUILDFILE"))
}

func TestBazelBuildExtractor_Extract_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(`java_library(name = "lib")`), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	pkgs, err := java.BazelBuildExtractor{}.Extract(f, extractor.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestBazelBuildExtractor_GetArtifact_ExtractsProjectDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create target directories with BUILD.bazel files
	fooDir := filepath.Join(root, "domains", "foo", "libs", "bar")
	require.NoError(t, os.MkdirAll(fooDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(fooDir, "BUILD.bazel"), []byte(""), 0600))

	quxDir := filepath.Join(root, "domains", "baz", "libs", "qux")
	require.NoError(t, os.MkdirAll(quxDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(quxDir, "BUILD.bazel"), []byte(""), 0600))

	// Create main BUILD.bazel with mixed deps
	buildContent := `java_library(
    name = "mylib",
    deps = [
        "//domains/foo/libs/bar",
        artifact("com.google.guava:guava"),
        "//domains/baz/libs/qux:qux-test-utils",
    ],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.ProjectDeps, 2)

	// Collect filenames for order-independent comparison
	depFiles := make([]string, len(artifact.ProjectDeps))
	for i, d := range artifact.ProjectDeps {
		depFiles[i] = d.Filename
	}
	assert.Contains(t, depFiles, filepath.Join(root, "domains", "foo", "libs", "bar", "BUILD.bazel"))
	assert.Contains(t, depFiles, filepath.Join(root, "domains", "baz", "libs", "qux", "BUILD.bazel"))
}

func TestBazelBuildExtractor_GetArtifact_VariableRefPattern(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create target directory
	libDir := filepath.Join(root, "libs", "common")
	require.NoError(t, os.MkdirAll(libDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "BUILD.bazel"), []byte(""), 0600))

	// Variable reference pattern — deps defined in a variable, then referenced
	buildContent := `LIBRARY_DEPS = [
    "//libs/common",
]

java_library(
    name = "mylib",
    deps = LIBRARY_DEPS,
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(root, "libs", "common", "BUILD.bazel"), artifact.ProjectDeps[0].Filename)
}

func TestBazelBuildExtractor_GetArtifact_SkipsNonExistentDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	buildContent := `java_library(
    name = "mylib",
    deps = [
        "//domains/nonexistent/lib",
    ],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestBazelBuildExtractor_GetArtifact_EmptyDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	buildContent := `java_library(
    name = "mylib",
    deps = [],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestBazelBuildExtractor_GetArtifact_MultipleDepsBlocks(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create target directories
	for _, dir := range []string{"libs/a", "libs/b", "libs/c"} {
		d := filepath.Join(root, dir)
		require.NoError(t, os.MkdirAll(d, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(d, "BUILD.bazel"), []byte(""), 0600))
	}

	buildContent := `java_library(
    name = "lib1",
    deps = [
        "//libs/a",
        "//libs/b",
    ],
)

java_library(
    name = "lib2",
    deps = [
        "//libs/b",
        "//libs/c",
    ],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.ProjectDeps, 3, "should have 3 unique deps across both blocks")

	depFiles := make([]string, len(artifact.ProjectDeps))
	for i, d := range artifact.ProjectDeps {
		depFiles[i] = d.Filename
	}
	assert.Contains(t, depFiles, filepath.Join(root, "libs", "a", "BUILD.bazel"))
	assert.Contains(t, depFiles, filepath.Join(root, "libs", "b", "BUILD.bazel"))
	assert.Contains(t, depFiles, filepath.Join(root, "libs", "c", "BUILD.bazel"))
}

func TestBazelBuildExtractor_GetArtifact_NoRootDir(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	buildContent := `java_library(
    name = "mylib",
    deps = ["//libs/foo"],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	// No RootDir set — should return artifact with no ProjectDeps
	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestBazelBuildExtractor_Integration_TransitiveClosure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create a mini BUILD.bazel graph:
	// A/BUILD.bazel -> deps = ["//B", "//C"]
	// B/BUILD.bazel -> deps = ["//D"]
	// C/BUILD.bazel -> deps = []
	// D/BUILD.bazel -> deps = []

	dirs := []string{"A", "B", "C", "D"}
	contents := map[string]string{
		"A": `java_library(name = "a", deps = ["//B", "//C"])`,
		"B": `java_library(name = "b", deps = ["//D"])`,
		"C": `java_library(name = "c", deps = [])`,
		"D": `java_library(name = "d", deps = [])`,
	}

	for _, dir := range dirs {
		d := filepath.Join(root, dir)
		require.NoError(t, os.MkdirAll(d, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(d, "BUILD.bazel"), []byte(contents[dir]), 0600))
	}

	ext := java.BazelBuildExtractor{}

	// Extract ProjectDeps for each file and build FileDependencies map
	fileDeps := make(map[string][]string)
	for _, dir := range dirs {
		buildPath := filepath.Join(root, dir, "BUILD.bazel")
		f, err := extractor.OpenLocalDepFile(buildPath)
		require.NoError(t, err)

		artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})
		f.Close()
		require.NoError(t, err)
		require.NotNil(t, artifact)

		var depPaths []string
		for _, dep := range artifact.ProjectDeps {
			depPaths = append(depPaths, dep.Filename)
		}
		fileDeps[buildPath] = depPaths
	}

	// Verify direct deps
	aPath := filepath.Join(root, "A", "BUILD.bazel")
	bPath := filepath.Join(root, "B", "BUILD.bazel")
	cPath := filepath.Join(root, "C", "BUILD.bazel")
	dPath := filepath.Join(root, "D", "BUILD.bazel")

	assert.Len(t, fileDeps[aPath], 2, "A should have 2 direct deps (B, C)")
	assert.Contains(t, fileDeps[aPath], bPath)
	assert.Contains(t, fileDeps[aPath], cPath)

	assert.Len(t, fileDeps[bPath], 1, "B should have 1 direct dep (D)")
	assert.Contains(t, fileDeps[bPath], dPath)

	assert.Empty(t, fileDeps[cPath], "C should have no deps")
	assert.Empty(t, fileDeps[dPath], "D should have no deps")
}

func TestBazelBuildExtractor_GetArtifact_SkipsLoadStatements(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create target directory for the real dep only — no directory for rules/java
	// so that if load() paths leaked through they would be silently skipped, but
	// we also create the rules dir to make the assertion stronger: even if the
	// path exists on disk, it must NOT appear in ProjectDeps.
	realDepDir := filepath.Join(root, "domains", "foo", "libs", "bar")
	require.NoError(t, os.MkdirAll(realDepDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(realDepDir, "BUILD.bazel"), []byte(""), 0600))

	rulesDir := filepath.Join(root, "rules", "java")
	require.NoError(t, os.MkdirAll(rulesDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(rulesDir, "BUILD.bazel"), []byte(""), 0600))

	buildContent := `load("//rules/java:defs.bzl", "dd_java_library")
load("//rules/trivy-db:defs.bzl", "trivy_db_version")

dd_java_library(
    name = "mylib",
    deps = [
        "//domains/foo/libs/bar",
    ],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.ProjectDeps, 1, "should only contain the real dep, not load() paths")
	assert.Equal(t, filepath.Join(root, "domains", "foo", "libs", "bar", "BUILD.bazel"), artifact.ProjectDeps[0].Filename)
}

func TestBazelBuildExtractor_GetArtifact_FallsBackToBUILD(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create target directory with BUILD (no .bazel extension)
	libDir := filepath.Join(root, "libs", "legacy")
	require.NoError(t, os.MkdirAll(libDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(libDir, "BUILD"), []byte(""), 0600))

	buildContent := `java_library(
    name = "mylib",
    deps = ["//libs/legacy"],
)
`
	buildFile := filepath.Join(root, "BUILD.bazel")
	require.NoError(t, os.WriteFile(buildFile, []byte(buildContent), 0600))

	f, err := extractor.OpenLocalDepFile(buildFile)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := java.BazelBuildExtractor{}.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(root, "libs", "legacy", "BUILD"), artifact.ProjectDeps[0].Filename)
}
