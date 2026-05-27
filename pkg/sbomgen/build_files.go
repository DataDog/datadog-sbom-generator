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

// exactFileTypes maps exact basenames to their FileType.
// build.gradle.kts is checked before build.gradle to avoid false matches.
var exactFileTypes = map[string]FileType{
	"pom.xml":          FileTypePomXML,
	"Cargo.toml":       FileTypeCargoToml,
	"package.json":     FileTypePackageJSON,
	"build.gradle.kts": FileTypeBuildGradleKts,
	"build.gradle":     FileTypeBuildGradle,
	"composer.json":    FileTypeComposerJSON,
	"Gemfile":          FileTypeGemfile,
	"Package.swift":    FileTypePackageSwift,
	"pyproject.toml":   FileTypePyprojectToml,
	"Pipfile":          FileTypePipfile,
	"requirements.txt": FileTypeRequirementsTxt,
}

// BuildFile identifies a build/manifest file within a repository.
type BuildFile struct {
	FileType FileType
	FilePath string // relative path within the repo (e.g. "backend/Cargo.toml")
	RepoPath string // absolute filesystem path of the repo root (empty when not available)
}

// fileTypeFromBasename returns the FileType for the given filename base,
// or ("", false) if the filename is not a recognized manifest type.
func fileTypeFromBasename(basename string) (FileType, bool) {
	// Check exact matches first.
	if ft, ok := exactFileTypes[basename]; ok {
		return ft, true
	}
	// Wildcard: *.csproj
	if strings.HasSuffix(basename, ".csproj") {
		return FileTypeCsproj, true
	}

	return "", false
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
// Each map key is a deduplicated BuildFile. Map values are empty slices
// (reserved for future transitive dependency tree support).
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

	for _, comp := range *bom.Components {
		if comp.Evidence == nil || comp.Evidence.Occurrences == nil {
			continue
		}
		for _, occ := range *comp.Evidence.Occurrences {
			var loc occurrenceLocation
			if err := json.Unmarshal([]byte(occ.Location), &loc); err != nil {
				continue
			}

			if loc.Block.Role == "lockfile" || loc.Block.FileName == "" {
				continue
			}

			basename := filepath.Base(loc.Block.FileName)
			ft, ok := fileTypeFromBasename(basename)
			if !ok {
				continue
			}

			if len(filterSet) > 0 {
				if _, match := filterSet[ft]; !match {
					continue
				}
			}

			bf := BuildFile{
				FileType: ft,
				FilePath: loc.Block.FileName,
			}
			if _, exists := result[bf]; !exists {
				result[bf] = []BuildFile{}
			}
		}
	}

	return result
}
