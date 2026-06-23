package dotnet

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectReferenceXMLUnmarshal(t *testing.T) {
	t.Parallel()

	csprojXML := []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\Common\Common.csproj" />
    <ProjectReference Include="..\Logging\Logging.csproj" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`)

	var csProj NugetCsProj
	err := xml.Unmarshal(csprojXML, &csProj)
	require.NoError(t, err)

	require.Len(t, csProj.ItemGroups, 2)

	// First ItemGroup should have ProjectReferences
	ig := csProj.ItemGroups[0]
	require.Len(t, ig.ProjectReferences, 2)
	require.NotNil(t, ig.ProjectReferences[0].IncludeAttr)
	assert.Equal(t, `..\Common\Common.csproj`, *ig.ProjectReferences[0].IncludeAttr)
	require.NotNil(t, ig.ProjectReferences[1].IncludeAttr)
	assert.Equal(t, `..\Logging\Logging.csproj`, *ig.ProjectReferences[1].IncludeAttr)

	// Second ItemGroup should have no ProjectReferences
	assert.Empty(t, csProj.ItemGroups[1].ProjectReferences)
}

// ============================================================================
// GetArtifact Tests
// ============================================================================

func TestNuGetCsprojExtractor_GetArtifact_ExtractsProjectDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create directory structure:
	// root/src/App/App.csproj -> references ../Common/Common.csproj and ../Logging/Logging.csproj
	// root/src/Common/Common.csproj
	// root/src/Logging/Logging.csproj
	appDir := filepath.Join(root, "src", "App")
	require.NoError(t, os.MkdirAll(appDir, 0700))

	commonDir := filepath.Join(root, "src", "Common")
	require.NoError(t, os.MkdirAll(commonDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(commonDir, "Common.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"></Project>`), 0600))

	loggingDir := filepath.Join(root, "src", "Logging")
	require.NoError(t, os.MkdirAll(loggingDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(loggingDir, "Logging.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"></Project>`), 0600))

	appCsproj := filepath.Join(appDir, "App.csproj")
	require.NoError(t, os.WriteFile(appCsproj, []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\Common\Common.csproj" />
    <ProjectReference Include="..\Logging\Logging.csproj" />
  </ItemGroup>
</Project>`), 0600))

	f, err := extractor.OpenLocalDepFile(appCsproj)
	require.NoError(t, err)
	defer f.Close()

	ext := NuGetCsprojExtractor{}
	artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Equal(t, f.Path(), artifact.Filename)
	assert.Equal(t, models.EcosystemNuGet, artifact.Ecosystem)
	require.Len(t, artifact.ProjectDeps, 2)

	depFiles := make([]string, len(artifact.ProjectDeps))
	for i, d := range artifact.ProjectDeps {
		depFiles[i] = d.Filename
	}
	assert.Contains(t, depFiles, filepath.Join(commonDir, "Common.csproj"))
	assert.Contains(t, depFiles, filepath.Join(loggingDir, "Logging.csproj"))
}

func TestNuGetCsprojExtractor_GetArtifact_ResolvesRelativePaths(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create deeply nested structure with .. segments
	// root/a/b/c/App.csproj references ..\..\Common\Common.csproj (= root/a/Common/Common.csproj)
	appDir := filepath.Join(root, "a", "b", "c")
	require.NoError(t, os.MkdirAll(appDir, 0700))

	commonDir := filepath.Join(root, "a", "Common")
	require.NoError(t, os.MkdirAll(commonDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(commonDir, "Common.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"></Project>`), 0600))

	appCsproj := filepath.Join(appDir, "App.csproj")
	require.NoError(t, os.WriteFile(appCsproj, []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\..\Common\Common.csproj" />
  </ItemGroup>
</Project>`), 0600))

	f, err := extractor.OpenLocalDepFile(appCsproj)
	require.NoError(t, err)
	defer f.Close()

	ext := NuGetCsprojExtractor{}
	artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.Len(t, artifact.ProjectDeps, 1)
	assert.Equal(t, filepath.Join(commonDir, "Common.csproj"), artifact.ProjectDeps[0].Filename)
}

func TestNuGetCsprojExtractor_GetArtifact_SkipsNonExistent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "src", "App")
	require.NoError(t, os.MkdirAll(appDir, 0700))

	appCsproj := filepath.Join(appDir, "App.csproj")
	require.NoError(t, os.WriteFile(appCsproj, []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\DoesNotExist\Missing.csproj" />
  </ItemGroup>
</Project>`), 0600))

	f, err := extractor.OpenLocalDepFile(appCsproj)
	require.NoError(t, err)
	defer f.Close()

	ext := NuGetCsprojExtractor{}
	artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestNuGetCsprojExtractor_GetArtifact_DeduplicatesDeps(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "src", "App")
	require.NoError(t, os.MkdirAll(appDir, 0700))

	commonDir := filepath.Join(root, "src", "Common")
	require.NoError(t, os.MkdirAll(commonDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(commonDir, "Common.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"></Project>`), 0600))

	// Two ItemGroups both reference the same project
	appCsproj := filepath.Join(appDir, "App.csproj")
	require.NoError(t, os.WriteFile(appCsproj, []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\Common\Common.csproj" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\Common\Common.csproj" />
  </ItemGroup>
</Project>`), 0600))

	f, err := extractor.OpenLocalDepFile(appCsproj)
	require.NoError(t, err)
	defer f.Close()

	ext := NuGetCsprojExtractor{}
	artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.Len(t, artifact.ProjectDeps, 1, "should deduplicate identical references")
}

func TestNuGetCsprojExtractor_GetArtifact_EmptyProjectRefs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appDir := filepath.Join(root, "src", "App")
	require.NoError(t, os.MkdirAll(appDir, 0700))

	// Only PackageReference, no ProjectReference
	appCsproj := filepath.Join(appDir, "App.csproj")
	require.NoError(t, os.WriteFile(appCsproj, []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`), 0600))

	f, err := extractor.OpenLocalDepFile(appCsproj)
	require.NoError(t, err)
	defer f.Close()

	ext := NuGetCsprojExtractor{}
	artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})

	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps)
}

func TestNuGetCsprojExtractor_IsManifestParser(t *testing.T) {
	t.Parallel()

	ext := NuGetCsprojExtractor{}
	assert.False(t, ext.IsManifestParser())
}

// ============================================================================
// Integration Test: Transitive Closure
// ============================================================================

func TestNuGetCsprojExtractor_Integration_TransitiveClosure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// Create a chain: A.csproj -> B.csproj -> C.csproj
	aDir := filepath.Join(root, "A")
	bDir := filepath.Join(root, "B")
	cDir := filepath.Join(root, "C")
	require.NoError(t, os.MkdirAll(aDir, 0700))
	require.NoError(t, os.MkdirAll(bDir, 0700))
	require.NoError(t, os.MkdirAll(cDir, 0700))

	require.NoError(t, os.WriteFile(filepath.Join(aDir, "A.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\B\B.csproj" />
  </ItemGroup>
</Project>`), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(bDir, "B.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <ProjectReference Include="..\C\C.csproj" />
  </ItemGroup>
</Project>`), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(cDir, "C.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>`), 0600))

	ext := NuGetCsprojExtractor{}

	// Extract ProjectDeps for each file and build FileDependencies map
	fileDeps := make(map[string][]string)
	for _, dir := range []struct {
		dir  string
		name string
	}{
		{aDir, "A.csproj"},
		{bDir, "B.csproj"},
		{cDir, "C.csproj"},
	} {
		csprojPath := filepath.Join(dir.dir, dir.name)
		f, err := extractor.OpenLocalDepFile(csprojPath)
		require.NoError(t, err)

		artifact, err := ext.GetArtifact(f, extractor.ScanContext{RootDir: root})
		f.Close()
		require.NoError(t, err)
		require.NotNil(t, artifact)

		var depPaths []string
		for _, dep := range artifact.ProjectDeps {
			depPaths = append(depPaths, dep.Filename)
		}
		fileDeps[csprojPath] = depPaths
	}

	aPath := filepath.Join(aDir, "A.csproj")
	bPath := filepath.Join(bDir, "B.csproj")
	cPath := filepath.Join(cDir, "C.csproj")

	assert.Len(t, fileDeps[aPath], 1, "A should have 1 direct dep (B)")
	assert.Contains(t, fileDeps[aPath], bPath)

	assert.Len(t, fileDeps[bPath], 1, "B should have 1 direct dep (C)")
	assert.Contains(t, fileDeps[bPath], cPath)

	assert.Empty(t, fileDeps[cPath], "C should have no project deps")
}
