package dotnet

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
)

// NugetCsprojMatcher matches the source file of a Nuget lockfile
// https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies

func (m NugetCsprojMatcher) GetSourceFile(sourceFile extractor.DepFile) (extractor.DepFile, error) {
	var dir = filepath.Dir(sourceFile.Path())

	var dirs, err = os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range dirs {
		if strings.HasSuffix(file.Name(), ".csproj") {
			return extractor.OpenLocalDepFile(filepath.Join(dir, file.Name()))
		}
	}

	return nil, errors.New("no csproj file found")
}

func (m NugetCsprojMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	// Extract all package details from the csproj file using the extractor
	extractedPackages, err := NuGetCsprojExtractor{}.Extract(sourceFile, context)
	if err != nil {
		return err
	}

	// Create two maps for lookup:
	// 1. By name+version (primary) - handles multiple versions of the same package
	// 2. By name only (fallback) - for packages without version in lock file
	extractedByNameAndVersion, extractedByName := indexCsprojPackages(extractedPackages)

	// Match lockfile packages with extracted csproj packages
	for key, pkg := range packages {
		if matchingPkg, ok := findExtractedMatch(pkg, extractedByNameAndVersion, extractedByName); ok {
			// Enrich packages found in the lockfile with information from the csproj
			packages[key].DepGroups = matchingPkg.DepGroups
			packages[key].TargetFrameworks = matchingPkg.TargetFrameworks
			packages[key].BlockLocation = matchingPkg.BlockLocation
			packages[key].LocationRole = matchingPkg.LocationRole
			packages[key].NameLocation = matchingPkg.NameLocation
			packages[key].VersionLocation = matchingPkg.VersionLocation
		}
	}

	return nil
}

func indexCsprojPackages(extractedPkgs []extractor.PackageDetails) (
	map[packageKey]extractor.PackageDetails,
	map[string]extractor.PackageDetails,
) {
	indexByNameAndVersion := make(map[packageKey]extractor.PackageDetails, len(extractedPkgs))
	indexByName := make(map[string]extractor.PackageDetails, len(extractedPkgs))

	for _, pkg := range extractedPkgs {
		setIfEarlier(indexByNameAndVersion, packageKey{name: pkg.Name, version: pkg.Version}, pkg)
		setIfEarlier(indexByName, pkg.Name, pkg)
	}

	return indexByNameAndVersion, indexByName
}

// Generic “keep the earliest occurrence by line number” helper.
func setIfEarlier[K comparable](indexMap map[K]extractor.PackageDetails, key K, pkg extractor.PackageDetails) {
	if existing, ok := indexMap[key]; !ok || pkg.BlockLocation.Line.Start < existing.BlockLocation.Line.Start {
		indexMap[key] = pkg
	}
}

func findExtractedMatch(
	pkg extractor.PackageDetails,
	indexByNameAndVersion map[packageKey]extractor.PackageDetails,
	indexByName map[string]extractor.PackageDetails,
) (extractor.PackageDetails, bool) {
	// Prefer exact name+version when lockfile has a version.
	if pkg.Version != "" {
		key := packageKey{name: pkg.Name, version: pkg.Version}
		if matchingPkg, ok := indexByNameAndVersion[key]; ok {
			return matchingPkg, true
		}
	}
	// Fallback: name-only match.
	matchingPkg, ok := indexByName[pkg.Name]

	return matchingPkg, ok
}

var _ extractor.Matcher = NugetCsprojMatcher{}
