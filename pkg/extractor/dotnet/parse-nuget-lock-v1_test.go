package dotnet_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/dotnet"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/stretchr/testify/assert"
)

func TestParseNuGetLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseNuGetLock_v1_InvalidJson(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/not-json.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseNuGetLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/empty.v1.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseNuGetLock_v1_OneFramework_OnePackage(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/one-framework-one-package/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_TwoPackages(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/one-framework-two-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_TwoPackages_BlockLocation(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/one-framework-two-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packagesByName := make(map[string]extractor.PackageDetails)
	for _, pkg := range packages {
		packagesByName[pkg.Name] = pkg
	}

	// Test.Core block: lines 5-10 within "net6.0" framework
	testCore := packagesByName["Test.Core"]
	assert.Equal(t, 5, testCore.BlockLocation.Line.Start)
	assert.Equal(t, 10, testCore.BlockLocation.Line.End)
	assert.Equal(t, 7, testCore.BlockLocation.Column.Start)
	assert.Equal(t, 8, testCore.BlockLocation.Column.End)
	assert.Contains(t, testCore.BlockLocation.Filename, "one-framework-two-packages")

	// Test.System block: lines 11-19 within "net6.0" framework
	testSystem := packagesByName["Test.System"]
	assert.Equal(t, 11, testSystem.BlockLocation.Line.Start)
	assert.Equal(t, 19, testSystem.BlockLocation.Line.End)
	assert.Equal(t, 7, testSystem.BlockLocation.Column.Start)
	assert.Equal(t, 8, testSystem.BlockLocation.Column.End)
	assert.Contains(t, testSystem.BlockLocation.Filename, "one-framework-two-packages")
}

func TestParseNuGetLock_v1_TwoFrameworks_MixedPackages(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/two-frameworks-mixed-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "2.15.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DifferentPackages(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/two-frameworks-different-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
		{
			Name:           "Test.System",
			Version:        "0.13.0-beta4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_TwoFrameworks_DuplicatePackages(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/two-frameworks-duplicate-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_OneFramework_OnePackage_MatchedFailed(t *testing.T) {
	t.Parallel()

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock NugetCsprojMatcher to fail
	matcherError := errors.New("NugetCsprojMatcher failed")
	nuGetExtractor := dotnet.NuGetLockExtractor{
		WithMatcher: extractor.WithMatcher{Matchers: []extractor.Matcher{testutil.FailingMatcher{Error: matcherError}}},
	}

	packages, err := extractor.ExtractFromFile("../fixtures/nuget/one-framework-one-package/packages.lock.json", nuGetExtractor)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "Test.Core",
			Version:        "6.0.5",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
		},
	})
}

func TestParseNuGetLock_v1_DevelopmentDependency(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/development-dependency-packages/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	absoluteCsprojPath, err := filepath.Abs("../fixtures/nuget/development-dependency-packages/development-dependency.csproj")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:             "Microsoft.TestPlatform.TestHost",
			Version:          "17.12.0",
			PackageManager:   models.NuGet,
			Ecosystem:        models.EcosystemNuGet,
			IsDirect:         true,
			DepGroups:        []string{string(models.DepGroupDev)},
			TargetFrameworks: []string{"net6.0"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 13},
				Column:   models.Position{Start: 3, End: 22},
				Filename: absoluteCsprojPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 30, End: 61},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 72, End: 79},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:             "Test.Core",
			Version:          "6.0.5",
			PackageManager:   models.NuGet,
			Ecosystem:        models.EcosystemNuGet,
			IsDirect:         true,
			DepGroups:        []string{string(models.DepGroupDev)},
			TargetFrameworks: []string{"net6.0"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 3, End: 79},
				Filename: absoluteCsprojPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 30, End: 39},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 50, End: 55},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:             "Test.System",
			Version:          "0.13.0-beta4",
			PackageManager:   models.NuGet,
			Ecosystem:        models.EcosystemNuGet,
			IsDirect:         true,
			DepGroups:        []string{string(models.DepGroupProd)},
			TargetFrameworks: []string{"net6.0"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 3, End: 68},
				Filename: absoluteCsprojPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 30, End: 41},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 52, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestMultipleVersionsNonDeterministicOrder(t *testing.T) {
	t.Parallel()

	packages, err := dotnet.ParseNuGetLock("../fixtures/nuget/multiple-versions-with-lockfile/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error parsing lock file: %v", err)
	}

	absoluteCsprojPath, err := filepath.Abs("../fixtures/nuget/multiple-versions-with-lockfile/test.csproj")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	absoluteLockfilePath, err := filepath.Abs("../fixtures/nuget/multiple-versions-with-lockfile/packages.lock.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:             "Newtonsoft.Json",
			Version:          "13.0.3",
			PackageManager:   models.NuGet,
			Ecosystem:        models.EcosystemNuGet,
			IsDirect:         true,
			DepGroups:        []string{string(models.DepGroupProd)},
			TargetFrameworks: []string{"net8.0"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 5, End: 68},
				Filename: absoluteCsprojPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 32, End: 47},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 58, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Microsoft.NETFramework.ReferenceAssemblies",
			Version:        "1.0.3",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 13},
				Column:   models.Position{Start: 7, End: 8},
				Filename: absoluteLockfilePath,
			},
			LocationRole: models.LocationRoleLockfile,
		},
		{
			Name:             "Newtonsoft.Json",
			Version:          "12.0.3",
			PackageManager:   models.NuGet,
			Ecosystem:        models.EcosystemNuGet,
			IsDirect:         true,
			DepGroups:        []string{string(models.DepGroupProd)},
			TargetFrameworks: []string{"net462", "net6.0"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 5, End: 68},
				Filename: absoluteCsprojPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 32, End: 47},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 58, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Microsoft.NETFramework.ReferenceAssemblies.net462",
			Version:        "1.0.3",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       false,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 20, End: 24},
				Column:   models.Position{Start: 7, End: 8},
				Filename: absoluteLockfilePath,
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}
