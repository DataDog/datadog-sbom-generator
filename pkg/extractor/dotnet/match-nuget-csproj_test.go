package dotnet_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/dotnet"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

var nugetCsprojMatcher = dotnet.NugetCsprojMatcher{}

func TestNugetCsprojMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/package-json/does-not-exist/npm-v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := nugetCsprojMatcher.GetSourceFile(lockFile)
	assert.Equal(t, "no csproj file found", err.Error())
	assert.Nil(t, sourceFile)
}

func TestNugetCsprojMatcher_GetSourceFile(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/nuget/one-framework-one-package-with-csproj/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := nugetCsprojMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/nuget/one-framework-one-package-with-csproj/"
	sourceFilePath := filepath.FromSlash(filepath.Join(dir, basePath+"project.csproj"))

	assert.Equal(t, sourceFile.Path(), sourceFilePath)
}

func TestNugetCsprojMatcher_Match_Packages(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/nuget/project.csproj")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "Downloader",
			PackageManager: models.NuGet,
		},
		{
			Name:           "MaterialDesignThemes",
			PackageManager: models.NuGet,
		},
		{
			Name:           "Test.Core",
			PackageManager: models.NuGet,
		},
	}
	err = nugetCsprojMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/nuget/"
	sourceFilePath := filepath.FromSlash(filepath.Join(dir, basePath+"project.csproj"))

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:             "Downloader",
			PackageManager:   models.NuGet,
			TargetFrameworks: []string{"net8.0-windows10.0.17763"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 3, End: 58},
				Filename: sourceFilePath,
			},
			LocationRole: models.LocationRoleManifest,
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 51, End: 54},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 30, End: 40},
				Filename: sourceFilePath,
			},
			DepGroups: []string{string(models.DepGroupProd)},
		},
		{
			Name:             "MaterialDesignThemes",
			PackageManager:   models.NuGet,
			TargetFrameworks: []string{"net8.0-windows10.0.17763"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 3, End: 90},
				Filename: sourceFilePath,
			},
			LocationRole: models.LocationRoleManifest,
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 61, End: 66},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 30, End: 50},
				Filename: sourceFilePath,
			},
			DepGroups: []string{string(models.DepGroupDev)},
		},
		{
			Name:             "Test.Core",
			PackageManager:   models.NuGet,
			TargetFrameworks: []string{"net8.0-windows10.0.17763"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 16},
				Column:   models.Position{Start: 5, End: 24},
				Filename: sourceFilePath,
			},
			LocationRole: models.LocationRoleManifest,
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 21},
				Filename: sourceFilePath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 25},
				Filename: sourceFilePath,
			},
			DepGroups: []string{string(models.DepGroupProd)},
		},
	})
}
