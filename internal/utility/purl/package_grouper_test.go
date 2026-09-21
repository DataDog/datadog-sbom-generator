package purl_test

import (
	"reflect"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/purl"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestGroupPackageByPURL_ShouldUnifyPackages(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/lockfile.xml",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					DepGroups: []string{"build"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(models.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/dir2/lockfile.json",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Vulnerabilities: []models.Vulnerability{
						{ID: "GHSA-456"},
					},
					DepGroups: []string{"test"},
				},
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:package-2",
						Ecosystem: string(models.EcosystemMaven),
						Version:   "1.0.0",
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)

	expected := map[string]models.PackageVulns{
		"pkg:maven/foo.bar/the-first-package@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:the-first-package",
				Version:   "1.0.0",
				Ecosystem: string(models.EcosystemMaven),
			},
			Vulnerabilities: []models.Vulnerability{
				{ID: "GHSA-456"},
			},
			DepGroups: []string{"build", "test"},
		},
		"pkg:maven/foo.bar/package-2@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:package-2",
				Version:   "1.0.0",
				Ecosystem: string(models.EcosystemMaven),
			},
		},
	}

	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}
	if len(result) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(result))
	}
	for expectedPURL, expectedInfo := range expected {
		info, exists := result[expectedPURL]

		if !exists {
			t.Errorf("Expected package %s to be in the results", expectedPURL)
		}
		if !reflect.DeepEqual(info, expectedInfo) {
			t.Errorf("Expected package %s to be %v, got %v", expectedPURL, expectedInfo, info)
		}
	}
}

func TestGroupPackageByPURL_ShouldKeepVersionConstraintsSeparate(t *testing.T) {
	t.Parallel()

	pkg := models.PackageInfo{
		Name:      "foo.bar:the-first-package",
		Version:   "1.0.0",
		Ecosystem: string(models.EcosystemMaven),
	}
	input := []models.PackageSource{
		{
			Packages: []models.PackageVulns{
				{
					Package: pkg,
					Metadata: map[models.PackageMetadataType]string{
						models.PackageManagerMetadata: "Maven",
					},
				},
				{
					Package: pkg,
					Locations: []models.PackageLocations{
						{Block: models.PackageLocation{Filename: "parent/pom.xml", LineStart: 18, LineEnd: 22}},
					},
					Metadata: map[models.PackageMetadataType]string{
						models.PackageManagerMetadata:    "Maven",
						models.VersionConstraintMetadata: "true",
					},
				},
				{
					Package: pkg,
					Locations: []models.PackageLocations{
						{Block: models.PackageLocation{Filename: "pom.xml", LineStart: 10, LineEnd: 14}},
					},
					Metadata: map[models.PackageMetadataType]string{
						models.PackageManagerMetadata:    "Maven",
						models.VersionConstraintMetadata: "true",
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)
	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}

	libraryKey := "pkg:maven/foo.bar/the-first-package@1.0.0"
	constraintKey := libraryKey + "#version-constraint"

	if len(result) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(result))
	}

	library, exists := result[libraryKey]
	if !exists {
		t.Errorf("Expected package %s to be in the results", libraryKey)
	}
	if library.Package.Purl != "" {
		t.Errorf("Group must not set Package.Purl, got %q", library.Package.Purl)
	}
	if _, ok := library.Metadata[models.VersionConstraintMetadata]; ok {
		t.Errorf("library key must not carry version-constraint metadata")
	}

	constraint, exists := result[constraintKey]
	if !exists {
		t.Errorf("Expected package %s to be in the results", constraintKey)
	}
	if constraint.Package.Purl != "" {
		t.Errorf("Group must not set Package.Purl, got %q", constraint.Package.Purl)
	}
	if constraint.Metadata[models.VersionConstraintMetadata] != "true" {
		t.Errorf("constraint key must keep version-constraint metadata")
	}
	if len(constraint.Locations) != 2 {
		t.Errorf("expected merged constraint locations, got %d", len(constraint.Locations))
	}
}

func TestGroupPackageByPURL_ShouldReportDependencyAsDirect(t *testing.T) {
	t.Parallel()
	input := []models.PackageSource{
		{
			Source: models.SourceInfo{
				Path: "/dir/lockfile.xml",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Metadata: map[models.PackageMetadataType]string{
						models.PackageManagerMetadata: "Maven",
					},
				},
			},
		},
		{
			Source: models.SourceInfo{
				Path: "/lockfile.xml",
			},
			Packages: []models.PackageVulns{
				{
					Package: models.PackageInfo{
						Name:      "foo.bar:the-first-package",
						Version:   "1.0.0",
						Ecosystem: string(models.EcosystemMaven),
					},
					Metadata: map[models.PackageMetadataType]string{
						models.PackageManagerMetadata:     "Maven",
						models.IsDirectDependencyMetadata: "true",
					},
				},
			},
		},
	}

	result, errors := purl.Group(input)

	expected := map[string]models.PackageVulns{
		"pkg:maven/foo.bar/the-first-package@1.0.0": {
			Package: models.PackageInfo{
				Name:      "foo.bar:the-first-package",
				Version:   "1.0.0",
				Ecosystem: string(models.EcosystemMaven),
			},
			Metadata: map[models.PackageMetadataType]string{
				models.PackageManagerMetadata:     "Maven",
				models.IsDirectDependencyMetadata: "true",
			},
		},
	}
	if len(errors) > 0 {
		t.Errorf("Unexpected errors: %v", errors)
	}
	if len(result) != len(expected) {
		t.Errorf("Expected %d packages, got %d", len(expected), len(result))
	}
	for expectedPURL, expectedInfo := range expected {
		info, exists := result[expectedPURL]

		if !exists {
			t.Errorf("Expected package %s to be in the results", expectedPURL)
		}
		if !reflect.DeepEqual(info, expectedInfo) {
			t.Errorf("Expected package %s to be %v, got %v", expectedPURL, expectedInfo, info)
		}
	}
}
