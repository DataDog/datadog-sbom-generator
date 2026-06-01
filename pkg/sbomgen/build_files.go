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

// occurrenceLocation is the subset of models.PackageLocations we need to parse
// from the SBOM occurrence location JSON string.
type occurrenceLocation struct {
	Block struct {
		FileName string `json:"file_name"`
		Role     string `json:"role"`
	} `json:"block"`
}

// GetBuildFileTrees parses a CycloneDX JSON SBOM and returns a map of all
// manifest build files found in component evidence occurrences.
//
// Build files are grouped by FileType and dispatched to a registered
// BuildFileProcessor for that type. Each processor receives deduplicated
// BuildFiles of its type and returns them enriched with their related files
// (e.g. sub-modules, parent POMs). Results from all processors are merged
// into the returned map.
//
// If no processor is registered for a FileType, a no-op processor is used
// that returns each file with an empty children slice.
//
// If filters are provided, only BuildFiles whose FileType matches one of
// the filters are included.
func GetBuildFileTrees(sbom []byte, filters ...FileType) map[BuildFile][]BuildFile {
	result := make(map[BuildFile][]BuildFile)

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

			ft := fileTypeFromBasename(filepath.Base(loc.Block.FileName))

			if len(filterSet) > 0 {
				if _, match := filterSet[ft]; !match {
					continue
				}
			}

			bf := BuildFile{
				FileType: ft,
				FilePath: loc.Block.FileName,
			}
			if _, exists := seen[bf]; !exists {
				seen[bf] = struct{}{}
				grouped[ft] = append(grouped[ft], bf)
			}
		}
	}

	// Dispatch each group to its registered processor and merge the results.
	for ft, files := range grouped {
		p, ok := processors[ft]
		if !ok {
			p = noopProcessor{}
		}
		for bf, children := range p.Process(files) {
			result[bf] = children
		}
	}

	return result
}
