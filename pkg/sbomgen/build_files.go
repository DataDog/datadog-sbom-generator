package sbomgen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	packageurl "github.com/package-url/packageurl-go"
)

// FileType represents a recognized build/manifest file type.
type FileType string

const (
	FileTypeBUILDBazel      FileType = "BUILD.bazel"
	FileTypeBUILD           FileType = "BUILD"
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
	FileTypeGoMod           FileType = "go.mod"
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

	// Track all file-type component paths so we can resolve cross-type
	// dependency targets in the second pass below.
	fileComponentPaths := make(map[string]struct{})

	for _, comp := range *bom.Components {
		// File-type components (produced by ExtractArtifactIds) represent
		// build/manifest files directly. Their BOMRef is the filename relative to
		// the repo root. Collect them so parent POMs with no package occurrences
		// are never missed.
		if comp.Type == cyclonedx.ComponentTypeFile && comp.BOMRef != "" {
			fileComponentPaths[comp.BOMRef] = struct{}{}
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

	// Second pass: resolve cross-type dependency targets to a fixed point.
	//
	// A file-type component may have a different basename than the lockfile
	// that depends on it (e.g. pyproject.toml is a dependency target of
	// requirements.txt). Such targets are missed by the first pass because
	// their FileType doesn't match the requesting file's FileType.
	//
	// We fix this by repeatedly scanning dependency edges of already-collected
	// files: if a dependency target is a known file-type component that hasn't
	// been added to a group yet, we add it under the same FileType as its
	// dependent so the processor can resolve it during BFS. We loop until no
	// new files are added (fixed point), resolving chains like:
	//   requirements.txt → libs/a/pyproject.toml → libs/b/pyproject.toml
	for {
		added := false
		for ft, files := range grouped {
			for _, f := range files {
				for _, depPath := range ctx.FileDependencies[f.FilePath] {
					if _, isFileComponent := fileComponentPaths[depPath]; !isFileComponent {
						continue
					}
					bf := BuildFile{FileType: ft, FilePath: depPath}
					if _, exists := seen[bf]; !exists {
						seen[bf] = struct{}{}
						grouped[ft] = append(grouped[ft], bf)
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
	}

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

// mavenPackageProperty is the CycloneDX component property name that records
// the package URL for a Maven file-type component. It mirrors the constant in
// internal/output/sbom/models.go; kept here to avoid an internal→pkg import
// cycle.
const mavenPackageProperty = "datadog:maven-package"

// parseArtifactID extracts an ecosystem-specific artifact identifier from a
// purl string. For purls with a namespace (e.g. Maven, npm) it returns
// "namespace:name"; for purls without a namespace (e.g. PyPI) it returns the
// name alone. Returns "" if the purl cannot be parsed.
func parseArtifactID(purl string) string {
	parsed, err := packageurl.FromString(purl)
	if err != nil || parsed.Name == "" {
		return ""
	}

	if parsed.Namespace != "" {
		return parsed.Namespace + ":" + parsed.Name
	}

	return parsed.Name
}

// buildProcessorContext extracts enrichment data from the SBOM into a
// ProcessorContext.
//
// FileDependencies is populated from bom.Dependencies for processors that need
// the raw dependency graph.
func buildProcessorContext(bom *cyclonedx.BOM) ProcessorContext {
	ctx := ProcessorContext{
		FileDependencies: make(map[string][]string),
		ArtifactIDs:      make(map[string]string),
	}

	for _, comp := range *bom.Components {
		if comp.Type != cyclonedx.ComponentTypeFile || comp.Properties == nil {
			continue
		}
		for _, prop := range *comp.Properties {
			if prop.Name == mavenPackageProperty && prop.Value != "" {
				if id := parseArtifactID(prop.Value); id != "" {
					ctx.ArtifactIDs[comp.BOMRef] = id
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

// AddNpmWorkspaceEdges enriches bom.Dependencies with inter-workspace dependency
// edges for npm/yarn/pnpm/bun monorepos. It must be called after the BOM is built
// but before serialization, while the scan root directory is still known.
//
// For each package.json file component in the BOM, this function reads the file
// from disk (joining rootDir with the relative bom-ref path), checks its
// dependencies against the workspace name→path index built from all file
// components' datadog:maven-package properties, and adds any missing edges to
// bom.Dependencies.
//
// This has no effect on normal package scanning or SBOM output — it only
// enriches the dependency graph used by GetBuildFileTrees.
func AddNpmWorkspaceEdges(bom *cyclonedx.BOM, rootDir string) {
	if bom.Components == nil {
		return
	}

	// Build index: npm package name → relative file path, from all file components.
	nameToPath := make(map[string]string)
	for _, comp := range *bom.Components {
		if comp.Type != cyclonedx.ComponentTypeFile || comp.Properties == nil {
			continue
		}
		for _, prop := range *comp.Properties {
			if prop.Name == mavenPackageProperty && prop.Value != "" {
				purl, err := packageurl.FromString(prop.Value)
				if err != nil {
					continue
				}
				name := purl.Name
				if purl.Namespace != "" {
					name = "@" + purl.Namespace + "/" + purl.Name
				}
				nameToPath[name] = comp.BOMRef
			}
		}
	}

	if len(nameToPath) == 0 {
		return
	}

	// Build existing dependency sets to avoid adding duplicate edges.
	existing := make(map[string]map[string]struct{})
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Dependencies == nil {
				continue
			}
			set := make(map[string]struct{}, len(*dep.Dependencies))
			for _, d := range *dep.Dependencies {
				set[d] = struct{}{}
			}
			existing[dep.Ref] = set
		}
	}

	// For each package.json file component, read it from disk and add edges
	// to any sibling workspace packages found in its dependencies.
	var newDeps []cyclonedx.Dependency
	for _, comp := range *bom.Components {
		if comp.Type != cyclonedx.ComponentTypeFile {
			continue
		}
		if filepath.Base(comp.BOMRef) != "package.json" {
			continue
		}

		absPath := filepath.Join(rootDir, comp.BOMRef)
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}

		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(data, &pkg); err != nil {
			continue
		}

		existingSet := existing[comp.BOMRef]
		var edges []string
		for depName := range pkg.Dependencies {
			if targetPath, ok := nameToPath[depName]; ok && targetPath != comp.BOMRef {
				if _, already := existingSet[targetPath]; !already {
					edges = append(edges, targetPath)
				}
			}
		}
		for depName := range pkg.DevDependencies {
			if targetPath, ok := nameToPath[depName]; ok && targetPath != comp.BOMRef {
				if _, already := existingSet[targetPath]; !already {
					edges = append(edges, targetPath)
				}
			}
		}

		if len(edges) == 0 {
			continue
		}

		if existingDep, ok := existing[comp.BOMRef]; ok {
			// Merge into existing dependency entry.
			for _, dep := range *bom.Dependencies {
				if dep.Ref == comp.BOMRef {
					updated := append(*dep.Dependencies, edges...)
					dep.Dependencies = &updated

					break
				}
			}
			for _, e := range edges {
				existingDep[e] = struct{}{}
			}
		} else {
			newDeps = append(newDeps, cyclonedx.Dependency{
				Ref:          comp.BOMRef,
				Dependencies: &edges,
			})
		}
	}

	if len(newDeps) > 0 {
		if bom.Dependencies == nil {
			bom.Dependencies = &newDeps
		} else {
			updated := append(*bom.Dependencies, newDeps...)
			bom.Dependencies = &updated
		}
	}
}
