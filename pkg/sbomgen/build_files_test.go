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
	val, ok := result[expected]
	if !ok {
		t.Fatalf("expected key %+v not found in result: %v", expected, result)
	}
	if val == nil {
		t.Error("expected non-nil empty slice, got nil")
	}
	if len(val) != 0 {
		t.Errorf("expected empty children slice, got %v", val)
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
		val, ok := result[expected]
		if !ok {
			t.Errorf("expected key %+v not found", expected)
		}
		if val == nil {
			t.Errorf("expected non-nil slice for %+v", expected)
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

func TestDefaultFileTypeFromFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename string
		expected FileType
		found    bool
	}{
		{"Cargo.toml", FileTypeCargoToml, true},
		{"package.json", FileTypePackageJSON, true},
		{"pom.xml", FileTypePomXML, true},
		{"build.gradle", FileTypeBuildGradle, true},
		{"build.gradle.kts", FileTypeBuildGradleKts, true},
		{"composer.json", FileTypeComposerJSON, true},
		{"Gemfile", FileTypeGemfile, true},
		{"Package.swift", FileTypePackageSwift, true},
		{"pyproject.toml", FileTypePyprojectToml, true},
		{"Pipfile", FileTypePipfile, true},
		{"requirements.txt", FileTypeRequirementsTxt, true},
		{"myapp.csproj", FileTypeCsproj, true},
		{"Some.Other.csproj", FileTypeCsproj, true},
		// Unknown files
		{"unknown.txt", "", false},
		{"Cargo.lock", "", false},
		{"yarn.lock", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			t.Parallel()
			ft, ok := fileTypeFromBasename(tt.filename)
			if ok != tt.found {
				t.Errorf("fileTypeFromBasename(%q) found=%v, want %v", tt.filename, ok, tt.found)
			}
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

func TestGetBuildFileTrees_UnknownManifestIgnored(t *testing.T) {
	t.Parallel()

	comp := componentWithOccurrences("something", "1.0.0",
		makeLocation("unknown-manifest.xyz", "manifest"),
	)
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom)

	if len(result) != 0 {
		t.Errorf("expected empty map for unknown manifest type, got %v", result)
	}
}
