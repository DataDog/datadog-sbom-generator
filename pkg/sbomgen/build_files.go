package sbomgen

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// FileType represents a recognized build/manifest file type.
type FileType string

const (
	FileTypePomXML          FileType = "pom.xml"
	FileTypeCargoToml       FileType = "Cargo.toml"
	FileTypePackageJSON     FileType = "package.json"
	FileTypeBuildGradle     FileType = "build.gradle"
	FileTypeBuildGradleKts  FileType = "build.gradle.kts"
	FileTypeComposerJSON    FileType = "composer.json"
	FileTypeGemfile         FileType = "Gemfile"
	FileTypePackageSwift    FileType = "Package.swift"
	FileTypePyprojectToml   FileType = "pyproject.toml"
	FileTypePipfile         FileType = "Pipfile"
	FileTypeRequirementsTxt FileType = "requirements.txt"
	FileTypeCsproj          FileType = "*.csproj"
)

// BuildFile identifies a build/manifest file within a repository.
type BuildFile struct {
	FileType FileType
	FilePath string // relative path within the repo (e.g. "backend/Cargo.toml")
	RepoPath string // absolute filesystem path of the repo root (empty when not available)
}

// fileTypeFromBasename returns the FileType for the given filename basename.
// For most files it is derived directly from the name (e.g. "Cargo.toml").
// Dynamic-name types with a known suffix or prefix pattern are normalised to
// their corresponding constant so callers can filter by FileType reliably:
//   - "*.csproj"            → FileTypeCsproj
//   - "requirements*.txt"   → FileTypeRequirementsTxt
func fileTypeFromBasename(basename string) FileType {
	if strings.HasSuffix(basename, ".csproj") {
		return FileTypeCsproj
	}

	if strings.HasPrefix(basename, "requirements") && strings.HasSuffix(basename, ".txt") {
		return FileTypeRequirementsTxt
	}

	return FileType(basename)
}

// addBuildFile adds a build file identified by filePath to the grouped map if it
// passes the filterSet check and has not been seen before.
func addBuildFile(filePath string, filterSet map[FileType]struct{}, seen map[BuildFile]struct{}, grouped map[FileType][]BuildFile) {
	ft := fileTypeFromBasename(filepath.Base(filePath))

	if len(filterSet) > 0 {
		if _, match := filterSet[ft]; !match {
			return
		}
	}

	bf := BuildFile{FileType: ft, FilePath: filePath}
	if _, exists := seen[bf]; !exists {
		seen[bf] = struct{}{}
		grouped[ft] = append(grouped[ft], bf)
	}
}

// occurrenceLocation is the subset of models.PackageLocations we need to parse
// from the SBOM occurrence location JSON string.
type occurrenceLocation struct {
	Block struct {
		FileName string `json:"file_name"`
		Role     string `json:"role"`
	} `json:"block"`
}

// GetBuildFileTrees parses a CycloneDX JSON SBOM and returns a map of all
// manifest build files found in component evidence occurrences, each enriched
// with its resolved relationships (parent, children).
//
// Build files are grouped by FileType and dispatched to a registered
// BuildFileProcessor for that type. Each processor receives deduplicated
// BuildFiles of its type and a ProcessorContext derived from the SBOM
// dependencies section, and returns the files enriched with their
// relationships. Results from all processors are merged into the returned map.
//
// If no processor is registered for a FileType, a no-op processor is used
// that returns each file with empty relations.
//
// If filters are provided, only BuildFiles whose FileType matches one of
// the filters are included.
func GetBuildFileTrees(sbom []byte, filters ...FileType) map[BuildFile]BuildFileRelations {
	result := make(map[BuildFile]BuildFileRelations)

	if len(sbom) == 0 {
		return result
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(sbom, &bom); err != nil {
		return result
	}

	if bom.Components == nil {
		return result
	}

	filterSet := make(map[FileType]struct{}, len(filters))
	for _, f := range filters {
		filterSet[f] = struct{}{}
	}

	// Collect build files grouped by FileType, deduplicating across components.
	grouped := make(map[FileType][]BuildFile)
	seen := make(map[BuildFile]struct{})

	for _, comp := range *bom.Components {
		// File-type components (produced by ExtractMavenPomArtifactIds) represent
		// build/manifest files directly. Their BOMRef is the filename relative to
		// the repo root. Collect them so parent POMs with no package occurrences
		// are never missed.
		if comp.Type == cyclonedx.ComponentTypeFile && comp.BOMRef != "" {
			addBuildFile(comp.BOMRef, filterSet, seen, grouped)
		}

		if comp.Evidence == nil || comp.Evidence.Occurrences == nil {
			continue
		}
		for _, occ := range *comp.Evidence.Occurrences {
			var loc occurrenceLocation
			if err := json.Unmarshal([]byte(occ.Location), &loc); err != nil {
				continue
			}

			if loc.Block.Role != "manifest" || loc.Block.FileName == "" {
				continue
			}

			addBuildFile(loc.Block.FileName, filterSet, seen, grouped)
		}
	}

	// Build the ProcessorContext from the SBOM dependencies section.
	ctx := buildProcessorContext(&bom)

	// Dispatch each group to its registered processor and merge the results.
	for ft, files := range grouped {
		p, ok := processors[ft]
		if !ok {
			p = noopProcessor{}
		}
		for bf, rels := range p.Process(files, ctx) {
			result[bf] = rels
		}
	}

	return result
}

// mavenParentPomProperty is the CycloneDX component property name that records
// the parent POM path for a Maven file-type component. It mirrors the constant
// in internal/output/sbom/models.go; kept here to avoid an internal→pkg import
// cycle.
const mavenParentPomProperty = "datadog:maven-parent-pom"

// osvScannerPackageProperty is the CycloneDX component property name that
// records the package URL for a file-type component. For Maven components the
// purl format is "pkg:maven/{groupId}/{artifactId}@{version}".
const osvScannerPackageProperty = "osv-scanner:package"

// buildProcessorContext extracts enrichment data from the SBOM into a
// ProcessorContext.
//
// FileDependencies is populated from bom.Dependencies for processors that need
// the raw dependency graph.
//
// parseMavenArtifactID extracts "groupId:artifactId" from a Maven purl.
// For example, "pkg:maven/com.example/my-module@1.0" yields "com.example:my-module".
// Returns "" if the purl is not a Maven purl or cannot be parsed.
func parseMavenArtifactID(purl string) string {
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]

	// Split into groupId/artifactId[@version]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ""
	}
	groupID := rest[:slash]
	artifactAndVersion := rest[slash+1:]

	// Strip @version if present.
	artifactID := artifactAndVersion
	if at := strings.IndexByte(artifactAndVersion, '@'); at >= 0 {
		artifactID = artifactAndVersion[:at]
	}

	if groupID == "" || artifactID == "" {
		return ""
	}

	return groupID + ":" + artifactID
}

func buildProcessorContext(bom *cyclonedx.BOM) ProcessorContext {
	ctx := ProcessorContext{
		FileDependencies: make(map[string][]string),
		MavenArtifactIDs: make(map[string]string),
	}

	for _, comp := range *bom.Components {
		if comp.Type != cyclonedx.ComponentTypeFile || comp.Properties == nil {
			continue
		}
		for _, prop := range *comp.Properties {
			if prop.Name == osvScannerPackageProperty && prop.Value != "" {
				if id := parseMavenArtifactID(prop.Value); id != "" {
					ctx.MavenArtifactIDs[comp.BOMRef] = id
				}
			}
		}
	}

	if bom.Dependencies == nil {
		return ctx
	}

	for _, dep := range *bom.Dependencies {
		if dep.Dependencies == nil {
			continue
		}

		ctx.FileDependencies[dep.Ref] = *dep.Dependencies
	}

	return ctx
}
