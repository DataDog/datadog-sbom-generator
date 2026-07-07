package sbom

import (
	"testing"

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
