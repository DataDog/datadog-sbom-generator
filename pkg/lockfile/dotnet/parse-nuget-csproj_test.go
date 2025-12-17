package dotnet_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/dotnet"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

func TestNuGetCsprojExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		path          string
		shouldExtract bool
	}{
		{
			name:          "empty path",
			path:          "",
			shouldExtract: false,
		},
		{
			name:          "simple csproj file",
			path:          "project.csproj",
			shouldExtract: true,
		},
		{
			name:          "csproj with path",
			path:          "path/to/my/project.csproj",
			shouldExtract: true,
		},
		{
			name:          "not a csproj file",
			path:          "path/to/my/project.vbproj",
			shouldExtract: false,
		},
		{
			name:          "csproj in filename but not extension",
			path:          "path.csproj.file",
			shouldExtract: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := dotnet.NuGetCsprojExtractor{}
			got := e.ShouldExtract(tt.path)
			assert.Equal(t, tt.shouldExtract, got)
		})
	}
}

func TestNuGetCsprojExtractor_SkipsWhenLockfileExists(t *testing.T) {
	t.Parallel()

	// This directory has both .csproj and packages.lock.json
	// The extractor should NOT extract the .csproj
	path := "../fixtures/nuget/one-framework-one-package-with-csproj/project.csproj"

	e := dotnet.NuGetCsprojExtractor{}
	shouldExtract := e.ShouldExtract(path)
	assert.False(t, shouldExtract, "ShouldExtract() should return false when packages.lock.json exists in the same directory")
}

func TestParseNuGetCsproj_Common(t *testing.T) {
	t.Parallel()

	path := "../fixtures/nuget/csproj-sample-app/Common/Common.csproj"
	packages, err := dotnet.ParseNuGetCsproj(path)
	if err != nil {
		t.Errorf("ParseNuGetCsproj() error = %v", err)
		return
	}

	absoluteCsprojPath, err := filepath.Abs(path)
	if err != nil {
		t.Errorf("filepath.Abs() error = %v", err)
		return
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "System.Text.Json",
			Version:        "8.0.4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 68},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 48},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 59, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "2.10.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 71},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 50, End: 67},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestParseNuGetCsproj_Logging(t *testing.T) {
	t.Parallel()

	path := "../fixtures/nuget/csproj-sample-app/Logging/Logging.csproj"
	packages, _ := dotnet.ParseNuGetCsproj(path)
	absoluteCsprojPath, _ := filepath.Abs(path)

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Microsoft.Extensions.Logging.Abstractions",
			Version:        "8.0.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 93},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 73},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 84, End: 89},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "3.1.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 59},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 50, End: 55},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestParseNuGetCsproj_SampleApp(t *testing.T) {
	t.Parallel()

	path := "../fixtures/nuget/csproj-sample-app/SampleApp/SampleApp.csproj"
	packages, _ := dotnet.ParseNuGetCsproj(path)
	absoluteCsprojPath, _ := filepath.Abs(path)

	// Expected packages:
	// - Newtonsoft.Json 13.0.3
	// - Serilog 3.1.1  - property substitution
	// - xunit 2.5.0
	// - coverlet.collector 3.2.0 (PrivateAssets=All, should be dev)
	// - Microsoft.CodeAnalysis.CSharp 4.9.0
	// - Dapper 2.1.28 - multi level property substitution from Directory.Packages.props
	//
	// Note: With .props file support, packages that previously had no version
	// can now be resolved from Directory.Packages.props

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Newtonsoft.Json",
			Version:        "13.0.3",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 5, End: 68},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 32, End: 47},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 58, End: 64},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "3.1.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 5, End: 71},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 50, End: 67},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "xunit",
			Version:        "2.5.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 5, End: 99},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 32, End: 37},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 48, End: 53},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "coverlet.collector",
			Version:        "3.2.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupDev)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 38, End: 38},
				Column:   models.Position{Start: 5, End: 103},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 38, End: 38},
				Column:   models.Position{Start: 32, End: 50},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 38, End: 38},
				Column:   models.Position{Start: 61, End: 79},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Microsoft.CodeAnalysis.CSharp",
			Version:        "4.9.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 41, End: 41},
				Column:   models.Position{Start: 5, End: 105},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 41, End: 41},
				Column:   models.Position{Start: 32, End: 61},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 41, End: 41},
				Column:   models.Position{Start: 72, End: 77},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Dapper",
			Version:        "2.1.28",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 71, End: 71},
				Column:   models.Position{Start: 5, End: 69},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 71, End: 71},
				Column:   models.Position{Start: 32, End: 38},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 71, End: 71},
				Column:   models.Position{Start: 49, End: 65},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "System.ServiceModel.Http",
			Version:        "4.10.3",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 50, End: 50},
				Column:   models.Position{Start: 5, End: 77},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 50, End: 50},
				Column:   models.Position{Start: 32, End: 56},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 50, End: 50},
				Column:   models.Position{Start: 67, End: 73},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "System.ServiceModel.Http",
			Version:        "8.1.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 5, End: 76},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 32, End: 56},
				Filename: absoluteCsprojPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 67, End: 72},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "xunit.assert",
			Version:        "$(XUnitVersion)",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 74, End: 74},
				Column:   models.Position{Start: 5, End: 82},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 74, End: 74},
				Column:   models.Position{Start: 32, End: 44},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestParseNuGetCsproj_SampleApp_CentralVersionManagement(t *testing.T) {
	t.Parallel()

	path := "../fixtures/nuget/csproj-sample-app-manage-versions-centrally/SampleApp/SampleApp.csproj"
	packages, _ := dotnet.ParseNuGetCsproj(path)
	absoluteCsprojPath, _ := filepath.Abs(path)

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "Newtonsoft.Json",
			Version:        "13.0.3",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 5, End: 51},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 32, End: 47},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "3.1.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 5, End: 43},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "xunit",
			Version:        "2.5.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 5, End: 83},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 32, End: 37},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "coverlet.collector",
			Version:        "3.2.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupDev)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 32, End: 32},
				Column:   models.Position{Start: 5, End: 74},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 32, End: 32},
				Column:   models.Position{Start: 32, End: 50},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Microsoft.CodeAnalysis.CSharp",
			Version:        "4.9.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 5, End: 89},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 32, End: 61},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Dapper",
			Version:        "2.1.28",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 59, End: 59},
				Column:   models.Position{Start: 5, End: 42},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 59, End: 59},
				Column:   models.Position{Start: 32, End: 38},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Microsoft.Extensions.Logging",
			Version:        "8.0.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 5, End: 64},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 32, End: 60},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestParseNuGetCsproj_Common_CentralVersionManagement(t *testing.T) {
	t.Parallel()

	path := "../fixtures/nuget/csproj-sample-app-manage-versions-centrally/Common/Common.csproj"
	packages, err := dotnet.ParseNuGetCsproj(path)
	if err != nil {
		t.Errorf("ParseNuGetCsproj() error = %v", err)
		return
	}

	absoluteCsprojPath, err := filepath.Abs(path)
	if err != nil {
		t.Errorf("filepath.Abs() error = %v", err)
		return
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "System.Text.Json",
			Version:        "6.0.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 52},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 48},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "System.Text.Json",
			Version:        "8.0.4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 52},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 48},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "3.1.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 43},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
		},
	})
}

func TestParseNuGetCsproj_Common_CentralVersionManagement_MultipleBuild(t *testing.T) {
	t.Parallel()
	r, err := reporter.New("cyclonedx-1-5", os.Stdout, os.Stderr, reporter.ErrorLevel, true)
	if err != nil {
		t.Errorf("Failed to create reporter = %v", err)
		return
	}
	rootDir, err := filepath.Abs("../fixtures/nuget/csproj-sample-app-multiple-build-props")
	if err != nil {
		t.Errorf("Failed to get absolute path = %v", err)
		return
	}

	context := lockfile.ScanContext{Reporter: r, RootDir: rootDir}
	path := "../fixtures/nuget/csproj-sample-app-multiple-build-props/com/Common/Common.csproj"
	packages, err := dotnet.ParseNuGetCsprojWithContext(path, context)
	if err != nil {
		t.Errorf("ParseNuGetCsprojWithContext() error = %v", err)
		return
	}

	absoluteCsprojPath, err := filepath.Abs(path)
	if err != nil {
		t.Errorf("filepath.Abs() error = %v", err)
		return
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "System.Text.Json",
			Version:        "6.0.0",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 52},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 48},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "System.Text.Json",
			Version:        "8.0.4",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 52},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 32, End: 48},
				Filename: absoluteCsprojPath,
			},
		},
		{
			Name:           "Serilog",
			Version:        "3.1.1",
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       true,
			DepGroups:      []string{string(models.DepGroupProd)},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 5, End: 43},
				Filename: absoluteCsprojPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 32, End: 39},
				Filename: absoluteCsprojPath,
			},
		},
	})

	// Now let's define a rootDir (which serve the upper bound of the scanner to traverse back, looking for .props files)
	// This should yield no results, as the rootDir is inside the csproj directory and thus no .props files are found
	otherRootDir, err := filepath.Abs("../fixtures/nuget/csproj-sample-app-multiple-build-props/com/Common")
	if err != nil {
		t.Errorf("Failed to get absolute path = %v", err)
		return
	}

	context = lockfile.ScanContext{Reporter: r, RootDir: otherRootDir}
	packages, err = dotnet.ParseNuGetCsprojWithContext(path, context)
	if err != nil {
		t.Errorf("ParseNuGetCsprojWithContext() error = %v", err)
		return
	}

	// No .props files should be found, which means no versions would be reported.
	// And without versions, we wouldn't report packages.
	assert.Empty(t, packages)
}
