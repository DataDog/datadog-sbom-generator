package dotnet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
)

// NugetCsprojMatcher matches the source file of a Nuget lockfile
// https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies

func (m NugetCsprojMatcher) GetSourceFile(sourceFile lockfile.DepFile) (lockfile.DepFile, error) {
	var dir = filepath.Dir(sourceFile.Path())

	var dirs, err = os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range dirs {
		if strings.HasSuffix(file.Name(), ".csproj") {
			return lockfile.OpenLocalDepFile(filepath.Join(dir, file.Name()))
		}
	}

	return nil, errors.New("no csproj file found")
}

func (m NugetCsprojMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	// Extract all package details from the csproj file using the extractor
	extractedPackages, err := NuGetCsprojExtractor{}.Extract(sourceFile, context)
	if err != nil {
		return err
	}

	// Create a map for quick lookup by package name
	extractedByName := make(map[string]lockfile.PackageDetails)
	for _, pkg := range extractedPackages {
		extractedByName[pkg.Name] = pkg
	}

	// Match lockfile packages with extracted csproj packages
	for key, pkg := range packages {
		extractedPkg, ok := extractedByName[pkg.Name]
		if !ok {
			continue
		}

		// Copy location information from the extracted package
		packages[key].DepGroups = extractedPkg.DepGroups
		packages[key].BlockLocation = extractedPkg.BlockLocation
		packages[key].NameLocation = extractedPkg.NameLocation
		packages[key].VersionLocation = extractedPkg.VersionLocation
	}

	return nil
}

var _ lockfile.Matcher = NugetCsprojMatcher{}
