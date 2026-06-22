package dotnet

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// IsManifestParser returns false — this extractor parses build files for
// internal project references, not manifest files.
func (e NuGetCsprojExtractor) IsManifestParser() bool {
	return false
}

// GetArtifact reads a .csproj file and extracts internal <ProjectReference>
// entries as ProjectDeps. Each reference is resolved to an absolute filesystem
// path relative to the .csproj file's directory. Non-existent targets are
// silently skipped. Duplicates are deduplicated.
func (e NuGetCsprojExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:  f.Path(),
			Ecosystem: models.EcosystemNuGet,
		},
	}

	artifact.ProjectDeps = extractCsprojInternalDeps(content, f.Path())

	return artifact, nil
}

// extractCsprojInternalDeps parses csproj XML content and returns ArtifactDetail
// entries for each <ProjectReference Include="..."> that resolves to an existing
// file on disk. Paths are resolved relative to the directory of csprojPath.
func extractCsprojInternalDeps(content []byte, csprojPath string) []models.ArtifactDetail {
	var csProj NugetCsProj
	if err := xml.Unmarshal(content, &csProj); err != nil {
		return nil
	}

	dir := filepath.Dir(csprojPath)

	var deps []models.ArtifactDetail
	seen := make(map[string]struct{})

	for _, ig := range csProj.ItemGroups {
		for _, ref := range ig.ProjectReferences {
			if ref.IncludeAttr == nil || *ref.IncludeAttr == "" {
				continue
			}

			// Normalize Windows backslashes to forward slashes
			include := strings.ReplaceAll(*ref.IncludeAttr, `\`, "/")

			// Resolve relative to the csproj file's directory
			resolved := filepath.Join(dir, include)
			resolved = filepath.Clean(resolved)

			// Verify the target file exists
			if _, err := os.Stat(resolved); err != nil {
				continue
			}

			// Deduplicate
			if _, dup := seen[resolved]; dup {
				continue
			}
			seen[resolved] = struct{}{}

			deps = append(deps, models.ArtifactDetail{Filename: resolved})
		}
	}

	return deps
}

// IsManifestParser returns false for NuGetLockExtractor — it parses lock files
// for package deps, not manifest files.
func (e NuGetLockExtractor) IsManifestParser() bool {
	return false
}

// GetArtifact finds the .csproj file adjacent to the packages.lock.json and
// extracts its internal <ProjectReference> entries as ProjectDeps. The returned
// artifact is keyed on the .csproj path (not the lock file path) so that
// GetBuildFileTrees groups it correctly under FileTypeCsproj. This mirrors the
// GradleLockExtractor pattern. If no .csproj is found, nil is returned.
func (e NuGetLockExtractor) GetArtifact(f extractor.DepFile, _ extractor.ScanContext) (*models.ScannedArtifact, error) {
	dir := filepath.Dir(f.Path())

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".csproj") {
			continue
		}
		csprojPath := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(csprojPath)
		if err != nil {
			continue
		}

		return &models.ScannedArtifact{
			ArtifactDetail: models.ArtifactDetail{
				Filename:  csprojPath,
				Ecosystem: models.EcosystemNuGet,
			},
			ProjectDeps: extractCsprojInternalDeps(content, csprojPath),
		}, nil
	}

	return nil, nil
}

var _ extractor.ArtifactExtractor = NuGetCsprojExtractor{}
var _ extractor.ManifestExtractor = NuGetCsprojExtractor{}
var _ extractor.ArtifactExtractor = NuGetLockExtractor{}
var _ extractor.ManifestExtractor = NuGetLockExtractor{}
