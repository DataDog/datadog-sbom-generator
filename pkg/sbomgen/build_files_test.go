package sbomgen

import (
	"encoding/json"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// locationBlock mirrors the JSON shape written by models.PackageLocations.
type locationBlock struct {
	FileName    string `json:"file_name"`
	LineStart   int    `json:"line_start"`
	LineEnd     int    `json:"line_end"`
	ColumnStart int    `json:"column_start"`
	ColumnEnd   int    `json:"column_end"`
	Role        string `json:"role"`
}

type locationWrapper struct {
	Block locationBlock `json:"block"`
}

// makeLocation builds a CycloneDX occurrence location JSON string
// matching the format produced by models.PackageLocations.MarshalToJSONString.
func makeLocation(fileName, role string) string {
	loc := locationWrapper{
		Block: locationBlock{
			FileName:    fileName,
			LineStart:   1,
			LineEnd:     1,
			ColumnStart: 1,
			ColumnEnd:   1,
			Role:        role,
		},
	}
	b, err := json.Marshal(loc)
	if err != nil {
		panic(err)
	}

	return string(b)
}

// makeSBOM builds minimal CycloneDX JSON bytes from a list of components.
func makeSBOM(components []cyclonedx.Component) []byte {
	bom := cyclonedx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cyclonedx.SpecVersion1_5,
		Components:  &components,
	}
	b, err := json.Marshal(bom)
	if err != nil {
		panic(err)
	}

	return b
}

// componentWithOccurrences creates a component with evidence occurrences.
func componentWithOccurrences(name, version string, locations ...string) cyclonedx.Component {
	occs := make([]cyclonedx.EvidenceOccurrence, len(locations))
	for i, loc := range locations {
		occs[i] = cyclonedx.EvidenceOccurrence{Location: loc}
	}

	return cyclonedx.Component{
		Name:    name,
		Version: version,
		Evidence: &cyclonedx.Evidence{
			Occurrences: &occs,
		},
	}
}

func TestGetBuildFileTrees_ManifestOnly(t *testing.T) {
	t.Parallel()

	comp := componentWithOccurrences("serde", "1.0.0",
		makeLocation("Cargo.toml", "manifest"),
		makeLocation("Cargo.lock", "lockfile"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	if len(result) != 1 {
		t.Fatalf("expected 1 build file, got %d: %v", len(result), result)
	}

	expected := BuildFile{
		FileType: FileTypeCargoToml,
		FilePath: "Cargo.toml",
	}
	rel, ok := result[expected]
	if !ok {
		t.Fatalf("expected key %+v not found in result: %v", expected, result)
	}
	if rel.Dependencies == nil {
		t.Error("expected non-nil Dependencies slice, got nil")
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected empty Dependencies slice, got %v", rel.Dependencies)
	}
}

func TestGetBuildFileTrees_OnlyLockfiles(t *testing.T) {
	t.Parallel()

	comp := componentWithOccurrences("serde", "1.0.0",
		makeLocation("Cargo.lock", "lockfile"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestGetBuildFileTrees_FilterByType(t *testing.T) {
	t.Parallel()

	comp1 := componentWithOccurrences("serde", "1.0.0",
		makeLocation("Cargo.toml", "manifest"),
	)
	comp2 := componentWithOccurrences("lodash", "4.0.0",
		makeLocation("package.json", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp1, comp2})

	result := GetBuildFileTrees(sbom, FileTypeCargoToml)

	if len(result) != 1 {
		t.Fatalf("expected 1 build file after filter, got %d: %v", len(result), result)
	}

	expected := BuildFile{FileType: FileTypeCargoToml, FilePath: "Cargo.toml"}
	if _, ok := result[expected]; !ok {
		t.Errorf("expected Cargo.toml key, got: %v", result)
	}
}

func TestGetBuildFileTrees_NoFilter(t *testing.T) {
	t.Parallel()

	comp1 := componentWithOccurrences("serde", "1.0.0",
		makeLocation("Cargo.toml", "manifest"),
	)
	comp2 := componentWithOccurrences("lodash", "4.0.0",
		makeLocation("package.json", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp1, comp2})

	result := GetBuildFileTrees(sbom)

	if len(result) != 2 {
		t.Fatalf("expected 2 build files, got %d: %v", len(result), result)
	}

	for _, expected := range []BuildFile{
		{FileType: FileTypeCargoToml, FilePath: "Cargo.toml"},
		{FileType: FileTypePackageJSON, FilePath: "package.json"},
	} {
		rel, ok := result[expected]
		if !ok {
			t.Errorf("expected key %+v not found", expected)
		}
		if rel.Dependencies == nil {
			t.Errorf("expected non-nil Dependencies slice for %+v", expected)
		}
	}
}

func TestGetBuildFileTrees_Deduplication(t *testing.T) {
	t.Parallel()

	// Two different components reference the same Cargo.toml manifest
	comp1 := componentWithOccurrences("serde", "1.0.0",
		makeLocation("Cargo.toml", "manifest"),
	)
	comp2 := componentWithOccurrences("tokio", "1.0.0",
		makeLocation("Cargo.toml", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp1, comp2})

	result := GetBuildFileTrees(sbom)

	if len(result) != 1 {
		t.Fatalf("expected 1 deduplicated build file, got %d: %v", len(result), result)
	}
}

func TestGetBuildFileTrees_EmptySBOM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input []byte
	}{
		{"nil input", nil},
		{"empty bytes", []byte{}},
		{"empty JSON object", []byte("{}")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := GetBuildFileTrees(tt.input)
			if result == nil {
				t.Error("expected non-nil empty map, got nil")
			}
			if len(result) != 0 {
				t.Errorf("expected empty map, got %v", result)
			}
		})
	}
}

func TestFileTypeFromBasename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename string
		expected FileType
	}{
		// Known exact types: FileType is the basename itself.
		{"Cargo.toml", FileTypeCargoToml},
		{"package.json", FileTypePackageJSON},
		{"pom.xml", FileTypePomXML},
		{"build.gradle", FileTypeBuildGradle},
		{"build.gradle.kts", FileTypeBuildGradleKts},
		{"composer.json", FileTypeComposerJSON},
		{"Gemfile", FileTypeGemfile},
		{"Package.swift", FileTypePackageSwift},
		{"pyproject.toml", FileTypePyprojectToml},
		{"Pipfile", FileTypePipfile},
		{"requirements.txt", FileTypeRequirementsTxt},
		// Dynamic suffix types: normalised to their constant.
		{"myapp.csproj", FileTypeCsproj},
		{"Some.Other.csproj", FileTypeCsproj},
		// requirements variants: normalised to FileTypeRequirementsTxt.
		{"requirements-dev.txt", FileTypeRequirementsTxt},
		{"requirements-test.txt", FileTypeRequirementsTxt},
		{"requirements_prod.txt", FileTypeRequirementsTxt},
		// Unknown files: returned as-is.
		{"unknown.txt", FileType("unknown.txt")},
		{"Cargo.lock", FileType("Cargo.lock")},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			t.Parallel()
			ft := fileTypeFromBasename(tt.filename)
			if ft != tt.expected {
				t.Errorf("fileTypeFromBasename(%q) = %q, want %q", tt.filename, ft, tt.expected)
			}
		})
	}
}

func TestGetBuildFileTrees_SubdirectoryPaths(t *testing.T) {
	t.Parallel()

	comp := componentWithOccurrences("serde", "1.0.0",
		makeLocation("backend/Cargo.toml", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	expected := BuildFile{FileType: FileTypeCargoToml, FilePath: "backend/Cargo.toml"}
	if _, ok := result[expected]; !ok {
		t.Errorf("expected key with subdirectory path, got: %v", result)
	}
}

func TestGetBuildFileTrees_CsprojWildcard(t *testing.T) {
	t.Parallel()

	comp := componentWithOccurrences("Newtonsoft.Json", "13.0.0",
		makeLocation("src/MyApp.csproj", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom, FileTypeCsproj)

	if len(result) != 1 {
		t.Fatalf("expected 1 csproj build file, got %d: %v", len(result), result)
	}

	expected := BuildFile{FileType: FileTypeCsproj, FilePath: "src/MyApp.csproj"}
	if _, ok := result[expected]; !ok {
		t.Errorf("expected csproj key, got: %v", result)
	}
}

func TestGetBuildFileTrees_RequirementsVariantsNormalized(t *testing.T) {
	t.Parallel()

	// requirements-dev.txt and requirements-test.txt are valid manifests
	// produced by RequirementsTxtExtractor; they must be reachable via the
	// FileTypeRequirementsTxt filter, not silently excluded.
	comp1 := componentWithOccurrences("requests", "2.31.0",
		makeLocation("requirements-dev.txt", "manifest"),
	)
	comp2 := componentWithOccurrences("pytest", "7.0.0",
		makeLocation("requirements-test.txt", "manifest"),
	)
	comp3 := componentWithOccurrences("flask", "3.0.0",
		makeLocation("requirements.txt", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp1, comp2, comp3})

	// Unfiltered: all three collapse to FileTypeRequirementsTxt.
	result := GetBuildFileTrees(sbom)
	if len(result) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(result), result)
	}
	for _, path := range []string{"requirements-dev.txt", "requirements-test.txt", "requirements.txt"} {
		bf := BuildFile{FileType: FileTypeRequirementsTxt, FilePath: path}
		if _, ok := result[bf]; !ok {
			t.Errorf("expected key %+v not found in result: %v", bf, result)
		}
	}

	// Filtered: all three are returned when filtering by FileTypeRequirementsTxt.
	filtered := GetBuildFileTrees(sbom, FileTypeRequirementsTxt)
	if len(filtered) != 3 {
		t.Fatalf("filtered: expected 3 entries, got %d: %v", len(filtered), filtered)
	}
}

func TestGetBuildFileTrees_UnknownManifestIncluded(t *testing.T) {
	t.Parallel()

	// Any file the SBOM marks as role=manifest is included, even if its type
	// is not one of the known FileType constants. The FileType is the basename.
	comp := componentWithOccurrences("something", "1.0.0",
		makeLocation("unknown-manifest.xyz", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	expected := BuildFile{FileType: FileType("unknown-manifest.xyz"), FilePath: "unknown-manifest.xyz"}
	if _, ok := result[expected]; !ok {
		t.Errorf("expected unknown manifest type to be included, got: %v", result)
	}
}

// fileTypeComponent creates a CycloneDX component of type "file" with the given
// BOMRef/Name, as produced by ExtractArtifactIds for manifest files.
func fileTypeComponent(filename string) cyclonedx.Component {
	return cyclonedx.Component{
		Type:   cyclonedx.ComponentTypeFile,
		BOMRef: filename,
		Name:   filename,
	}
}

func TestGetBuildFileTrees_FileTypeComponentCollected(t *testing.T) {
	t.Parallel()

	// A file-type component with no evidence occurrences (e.g. a parent POM that
	// declares no dependencies and never appears in package occurrence locations).
	comp := fileTypeComponent("pom.xml")
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 1 {
		t.Fatalf("expected 1 build file from file-type component, got %d: %v", len(result), result)
	}
	expected := BuildFile{FileType: FileTypePomXML, FilePath: "pom.xml"}
	if _, ok := result[expected]; !ok {
		t.Errorf("expected key %+v not found in result: %v", expected, result)
	}
}

func TestGetBuildFileTrees_FileTypeComponentDeduplicatedWithOccurrence(t *testing.T) {
	t.Parallel()

	// When the same file appears both as a file-type component and in an
	// occurrence of a package component, it must be deduplicated to one entry.
	fileComp := fileTypeComponent("pom.xml")
	pkgComp := componentWithOccurrences("com.example:child", "1.0.0",
		makeLocation("pom.xml", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{fileComp, pkgComp})

	result := GetBuildFileTrees(sbom, FileTypePomXML)

	if len(result) != 1 {
		t.Fatalf("expected 1 deduplicated entry, got %d: %v", len(result), result)
	}
}

// stubbedProcessor is a BuildFileProcessor that records received files and
// returns them with a fixed sentinel child for easy assertion in tests.
type stubbedProcessor struct {
	received []BuildFile
	child    BuildFile
}

func (p *stubbedProcessor) Process(files []BuildFile, _ ProcessorContext) map[BuildFile]BuildFileRelations {
	p.received = append(p.received, files...)
	result := make(map[BuildFile]BuildFileRelations, len(files))
	for _, f := range files {
		result[f] = BuildFileRelations{Dependencies: []BuildFileWithHopCount{{BuildFile: p.child, HopCount: 1}}}
	}

	return result
}

//nolint:paralleltest // mutates the global processors registry; cannot run in parallel
func TestGetBuildFileTrees_RegisteredProcessorIsCalled(t *testing.T) {
	sentinel := BuildFile{FileType: FileType("sentinel"), FilePath: "sentinel"}
	stub := &stubbedProcessor{child: sentinel}

	const testType FileType = "test-manifest.xyz"
	RegisterBuildFileProcessor(testType, stub)
	defer delete(processors, testType)

	comp := componentWithOccurrences("pkg", "1.0.0",
		makeLocation("test-manifest.xyz", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	expected := BuildFile{FileType: testType, FilePath: "test-manifest.xyz"}
	rel, ok := result[expected]
	if !ok {
		t.Fatalf("expected key %+v not found", expected)
	}
	if len(rel.Dependencies) != 1 || rel.Dependencies[0].BuildFile != sentinel {
		t.Errorf("expected sentinel dependency, got %v", rel.Dependencies)
	}
	if len(stub.received) != 1 || stub.received[0] != expected {
		t.Errorf("processor received unexpected files: %v", stub.received)
	}
}

func TestParseArtifactID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		purl     string
		expected string
	}{
		{
			name:     "Maven purl returns namespace:name",
			purl:     "pkg:maven/com.example/my-module@1.0",
			expected: "com.example:my-module",
		},
		{
			name:     "Maven purl without version",
			purl:     "pkg:maven/com.example/my-module",
			expected: "com.example:my-module",
		},
		{
			name:     "PyPI purl returns name only",
			purl:     "pkg:pypi/mylib@1.0",
			expected: "mylib",
		},
		{
			name:     "PyPI purl without version",
			purl:     "pkg:pypi/mylib",
			expected: "mylib",
		},
		{
			name:     "npm purl with namespace returns namespace:name",
			purl:     "pkg:npm/%40angular/core@12.0.0",
			expected: "@angular:core",
		},
		{
			name:     "npm purl without namespace returns name only",
			purl:     "pkg:npm/lodash@4.17.21",
			expected: "lodash",
		},
		{
			name:     "invalid purl returns empty",
			purl:     "not-a-purl",
			expected: "",
		},
		{
			name:     "empty string returns empty",
			purl:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseArtifactID(tt.purl)
			if got != tt.expected {
				t.Errorf("parseArtifactID(%q) = %q, want %q", tt.purl, got, tt.expected)
			}
		})
	}
}
