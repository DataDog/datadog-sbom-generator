package sbomgen

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

// gradleFileComponent creates a file-type CycloneDX component representing a
// build.gradle or build.gradle.kts, as produced by GetArtifact on the Gradle
// extractor. The osv-scanner:package property encodes the group:artifact as a
// Maven purl so that buildProcessorContext populates MavenArtifactIDs.
func gradleFileComponent(buildFilePath, groupArtifact string) cyclonedx.Component {
	props := []cyclonedx.Property{
		{Name: osvScannerPackageProperty, Value: "pkg:maven/" + groupArtifact + "@1.0"},
	}

	return cyclonedx.Component{
		Type:       cyclonedx.ComponentTypeFile,
		BOMRef:     buildFilePath,
		Name:       buildFilePath,
		Properties: &props,
	}
}

// gradleComponent builds a CycloneDX component with a manifest occurrence for
// the given build.gradle path, as the SBOM generator would emit it.
func gradleComponent(name, buildFilePath string) cyclonedx.Component {
	return componentWithOccurrences(name, "1.0.0", makeLocation(buildFilePath, "manifest"))
}

// gradleFile is a shorthand for a build.gradle BuildFile with no RepoPath.
func gradleFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeBuildGradle, FilePath: path}
}

// gradleKtsFile is a shorthand for a build.gradle.kts BuildFile with no RepoPath.
func gradleKtsFile(path string) BuildFile {
	return BuildFile{FileType: FileTypeBuildGradleKts, FilePath: path}
}

// TestGradleProcessor_BuildGradle_IDPopulated verifies that a build.gradle
// with a group property gets its ID populated from the osv-scanner:package purl.
func TestGradleProcessor_BuildGradle_IDPopulated(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		gradleFileComponent("build.gradle", "com.example/myproject"),
		gradleComponent("org.springframework:spring-core", "build.gradle"),
	})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradle)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[gradleFile("build.gradle")]
	if rel.ID != "com.example:myproject" {
		t.Errorf("expected ID=com.example:myproject, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}

// TestGradleProcessor_BuildGradleKts_IDPopulated verifies that a
// build.gradle.kts with a group property gets its ID populated.
func TestGradleProcessor_BuildGradleKts_IDPopulated(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		gradleFileComponent("build.gradle.kts", "com.example/myproject"),
		gradleComponent("org.springframework:spring-core", "build.gradle.kts"),
	})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradleKts)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[gradleKtsFile("build.gradle.kts")]
	if rel.ID != "com.example:myproject" {
		t.Errorf("expected ID=com.example:myproject, got %q", rel.ID)
	}
	if len(rel.Dependencies) != 0 {
		t.Errorf("expected no Dependencies, got %v", rel.Dependencies)
	}
}

// TestGradleProcessor_NoID_EmptyString verifies that a file-type component
// without osv-scanner:package results in an empty ID.
func TestGradleProcessor_NoID_EmptyString(t *testing.T) {
	t.Parallel()

	// File component with no properties at all
	comp := cyclonedx.Component{
		Type:   cyclonedx.ComponentTypeFile,
		BOMRef: "build.gradle",
		Name:   "build.gradle",
	}
	sbom := makeSBOM([]cyclonedx.Component{comp})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradle)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(result), result)
	}

	rel := result[gradleFile("build.gradle")]
	if rel.ID != "" {
		t.Errorf("expected empty ID, got %q", rel.ID)
	}
}

// TestGradleProcessor_Dependencies_AlwaysEmpty verifies that Gradle processor
// always returns empty Dependencies (no inter-project hierarchy).
func TestGradleProcessor_Dependencies_AlwaysEmpty(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		gradleFileComponent("build.gradle", "com.example/root"),
		gradleFileComponent("module-a/build.gradle", "com.example/module-a"),
		gradleComponent("com.example:root", "build.gradle"),
		gradleComponent("com.example:module-a", "module-a/build.gradle"),
	})

	result := GetBuildFileTrees(sbom, FileTypeBuildGradle)

	if len(result) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(result), result)
	}

	for bf, rel := range result {
		if len(rel.Dependencies) != 0 {
			t.Errorf("%s: expected empty Dependencies, got %v", bf.FilePath, rel.Dependencies)
		}
	}
}

// TestGradleProcessor_BothFileTypesRegistered verifies that GetBuildFileTrees
// returns entries for both build.gradle and build.gradle.kts when present.
func TestGradleProcessor_BothFileTypesRegistered(t *testing.T) {
	t.Parallel()

	sbom := makeSBOM([]cyclonedx.Component{
		gradleFileComponent("app/build.gradle", "com.example/app"),
		gradleFileComponent("lib/build.gradle.kts", "com.example/lib"),
		gradleComponent("com.example:dep-a", "app/build.gradle"),
		gradleComponent("com.example:dep-b", "lib/build.gradle.kts"),
	})

	result := GetBuildFileTrees(sbom)

	expectedGradle := BuildFile{FileType: FileTypeBuildGradle, FilePath: "app/build.gradle"}
	expectedKts := BuildFile{FileType: FileTypeBuildGradleKts, FilePath: "lib/build.gradle.kts"}

	if _, ok := result[expectedGradle]; !ok {
		t.Errorf("expected build.gradle entry, got: %v", result)
	}
	if _, ok := result[expectedKts]; !ok {
		t.Errorf("expected build.gradle.kts entry, got: %v", result)
	}

	relGradle := result[expectedGradle]
	if relGradle.ID != "com.example:app" {
		t.Errorf("build.gradle: expected ID=com.example:app, got %q", relGradle.ID)
	}
	relKts := result[expectedKts]
	if relKts.ID != "com.example:lib" {
		t.Errorf("build.gradle.kts: expected ID=com.example:lib, got %q", relKts.ID)
	}
}
