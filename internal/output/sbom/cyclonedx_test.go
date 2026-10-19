package sbom

import (
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// TestBuildCycloneDXBom_RubySelfGem_NoDanglingLockfileDep guards against the
// regression where a standard gem project (gemspec form in Gemfile) produced a
// dangling Gemfile.lock→Gemfile dependency in the CycloneDX SBOM.
//
// When a gem's Gemfile.lock contains the project gem itself in a PATH section,
// the gem's BlockLocation.Filename is Gemfile.lock. Setting artifact.PackageName
// (not artifact.Name) ensures findArtifact never matches the self-gem, so
// createFileComponents never emits a Ref="Gemfile.lock" dependency that has no
// corresponding file component.
func TestBuildCycloneDXBom_RubySelfGem_NoDanglingLockfileDep(t *testing.T) {
	t.Parallel()

	// The Gemfile artifact uses PackageName (not Name) so findArtifact won't match.
	artifact := models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:    "Gemfile",
			Ecosystem:   models.EcosystemRubyGems,
			PackageName: "my_gem",
			// Name is intentionally empty — Ruby artifacts must not participate in
			// findArtifact cross-project matching.
		},
	}

	// The self-gem appears in Gemfile.lock (PATH section); its BlockLocation is
	// the lockfile, not the Gemfile.
	selfGem := models.PackageVulns{
		Package: models.PackageInfo{
			Name:    "my_gem",
			Version: "1.0.0",
		},
		Locations: []models.PackageLocations{
			{
				Block: models.PackageLocation{
					Filename:  "Gemfile.lock",
					LineStart: 5,
					LineEnd:   5,
				},
			},
		},
	}

	bom := BuildCycloneDXBom(
		Tool{Name: "test", Version: "0"},
		map[string]models.PackageVulns{"pkg:gem/my_gem@1.0.0": selfGem},
		[]models.ScannedArtifact{artifact},
	)

	// The only file component emitted should be Gemfile, not Gemfile.lock.
	for _, comp := range *bom.Components {
		if comp.BOMRef == "Gemfile.lock" {
			t.Errorf("unexpected file component for Gemfile.lock — lockfile must not be emitted as a file component")
		}
	}

	// No dependency entry should reference Gemfile.lock as a Ref.
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			if dep.Ref == "Gemfile.lock" {
				t.Errorf("dangling dependency: Ref=%q → %v; Gemfile.lock must not appear as a dependency source", dep.Ref, *dep.Dependencies)
			}
		}
	}
}

func TestBuildCycloneDXBom_VersionConstraintOnInternalModule_NoDependencyEdge(t *testing.T) {
	t.Parallel()

	core := models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      "com.example:core",
			Version:   "1.0.0",
			Filename:  "core/pom.xml",
			Ecosystem: models.EcosystemMaven,
		},
	}
	pin := models.PackageVulns{
		Package: models.PackageInfo{
			Name:      "com.example:core",
			Version:   "1.0.0",
			Ecosystem: string(models.EcosystemMaven),
		},
		Metadata: models.PackageMetadata{models.VersionConstraintMetadata: "true"},
		Locations: []models.PackageLocations{
			{Block: models.PackageLocation{Filename: "pom.xml", LineStart: 10, LineEnd: 14}},
		},
	}

	bom := BuildCycloneDXBom(
		Tool{Name: "test", Version: "0"},
		map[string]models.PackageVulns{"pkg:maven/com.example/core@1.0.0#version-constraint": pin},
		[]models.ScannedArtifact{core},
	)

	for _, dep := range *bom.Dependencies {
		if dep.Ref == "pom.xml" {
			t.Errorf("unexpected dependency edge from a version constraint: %s -> %v", dep.Ref, *dep.Dependencies)
		}
	}
}

// TestBuildCycloneDXBom_RubyArtifact_PackageNameProperty verifies that
// PackageName is emitted as the datadog:maven-package property on the Gemfile
// file component, enabling ctx.ArtifactIDs and BuildFileRelations.ID.
func TestBuildCycloneDXBom_RubyArtifact_PackageNameProperty(t *testing.T) {
	t.Parallel()

	artifact := models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:    "Gemfile",
			Ecosystem:   models.EcosystemRubyGems,
			PackageName: "my_gem",
		},
	}

	bom := BuildCycloneDXBom(
		Tool{Name: "test", Version: "0"},
		map[string]models.PackageVulns{},
		[]models.ScannedArtifact{artifact},
	)

	for _, comp := range *bom.Components {
		if comp.BOMRef != "Gemfile" {
			continue
		}
		if comp.Properties == nil {
			t.Fatal("Gemfile component has no properties; expected datadog:maven-package")
		}
		for _, prop := range *comp.Properties {
			if prop.Name == mavenPackageProperty {
				if prop.Value == "" {
					t.Error("datadog:maven-package property is empty")
				}

				return
			}
		}
		t.Errorf("datadog:maven-package property not found on Gemfile component; properties: %v", *comp.Properties)

		return
	}

	t.Error("Gemfile file component not found in SBOM components")
}

func TestBuildCycloneDXBom_VersionConstraintLibrary(t *testing.T) {
	t.Parallel()

	libraryPURL := "pkg:maven/com.google.code.findbugs/jsr305@3.0.2"
	constraintKey := libraryPURL + "#version-constraint"
	pin := models.PackageVulns{
		Package: models.PackageInfo{
			Name:      "com.google.code.findbugs:jsr305",
			Version:   "3.0.2",
			Ecosystem: string(models.EcosystemMaven),
		},
		Metadata: models.PackageMetadata{
			models.VersionConstraintMetadata: "true",
			models.PackageManagerMetadata:    "Maven",
		},
		Locations: []models.PackageLocations{
			{
				Block: models.PackageLocation{
					Filename:    "pom.xml",
					LineStart:   18,
					LineEnd:     22,
					ColumnStart: 7,
					ColumnEnd:   20,
					Role:        models.LocationRoleManifest,
				},
				Name: &models.PackageLocation{
					Filename:    "pom.xml",
					LineStart:   20,
					LineEnd:     20,
					ColumnStart: 21,
					ColumnEnd:   27,
					Role:        models.LocationRoleManifest,
				},
				Version: &models.PackageLocation{
					Filename:    "pom.xml",
					LineStart:   21,
					LineEnd:     21,
					ColumnStart: 18,
					ColumnEnd:   23,
					Role:        models.LocationRoleManifest,
				},
			},
		},
	}

	bom := BuildCycloneDXBom(
		Tool{Name: "test", Version: "0"},
		map[string]models.PackageVulns{constraintKey: pin},
		nil,
	)

	var component cyclonedx.Component
	found := false
	for _, comp := range *bom.Components {
		if comp.BOMRef == constraintKey {
			component = comp
			found = true

			break
		}
	}
	if !found {
		t.Fatal("version-constraint library component not found")
	}

	if component.Type != libraryComponentType {
		t.Errorf("Type = %q, want %q", component.Type, libraryComponentType)
	}
	if component.PackageURL != libraryPURL {
		t.Errorf("PackageURL = %q, want %q", component.PackageURL, libraryPURL)
	}

	gotProps := map[string]string{}
	if component.Properties == nil {
		t.Fatal("expected datadog properties on constraint component")
	}
	for _, prop := range *component.Properties {
		gotProps[prop.Name] = prop.Value
	}
	if gotProps["datadog:version-constraint"] != "true" {
		t.Errorf("missing datadog:version-constraint=true, properties=%v", gotProps)
	}
	if gotProps["datadog:package-manager"] != "Maven" {
		t.Errorf("missing datadog:package-manager=Maven, properties=%v", gotProps)
	}
	if _, ok := gotProps["datadog:is-direct"]; ok {
		t.Errorf("constraint must not emit is-direct, properties=%v", gotProps)
	}

	if component.Evidence == nil || component.Evidence.Occurrences == nil || len(*component.Evidence.Occurrences) != 1 {
		t.Fatal("expected one evidence occurrence with block/name/version")
	}
	locationJSON := (*component.Evidence.Occurrences)[0].Location
	for _, want := range []string{`"block"`, `"name"`, `"version"`} {
		if !strings.Contains(locationJSON, want) {
			t.Errorf("evidence location missing %s: %s", want, locationJSON)
		}
	}
}
