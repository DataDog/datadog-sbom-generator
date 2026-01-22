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

	// Create two maps for lookup:
	// 1. By name+version (primary) - handles multiple versions of the same package
	// 2. By name only (fallback) - for packages without version in lock file
	extractedByNameAndVersion := make(map[packageKey]lockfile.PackageDetails)
	extractedByName := make(map[string]lockfile.PackageDetails)
	for _, pkg := range extractedPackages {
		key := packageKey{name: pkg.Name, version: pkg.Version}

		// For duplicate name+version combinations, keep the first occurrence (lowest line number)
		// This ensures deterministic behavior when the same package appears multiple times
		// That's necessary because a PackageDetails only support one location, and in the lockfile
		// we do not report the multiple target-framework. So we pick the first location only.
		if existing, exists := extractedByNameAndVersion[key]; exists {
			// Keep the package with the lower line number
			if pkg.BlockLocation.Line.Start < existing.BlockLocation.Line.Start {
				extractedByNameAndVersion[key] = pkg
			}
		} else {
			extractedByNameAndVersion[key] = pkg
		}

		// For name-only map, also keep the first occurrence by line number
		// This maintains backward compatibility for packages without versions
		if existing, exists := extractedByName[pkg.Name]; exists {
			if pkg.BlockLocation.Line.Start < existing.BlockLocation.Line.Start {
				extractedByName[pkg.Name] = pkg
			}
		} else {
			extractedByName[pkg.Name] = pkg
		}
	}

	// Match lockfile packages with extracted csproj packages
	for key, pkg := range packages {
		var extractedPkg lockfile.PackageDetails
		var ok bool

		// Try exact match by name+version first
		if pkg.Version != "" {
			lookupKey := packageKey{name: pkg.Name, version: pkg.Version}
			extractedPkg, ok = extractedByNameAndVersion[lookupKey]
		}

		// Fall back to name-only match if version match failed or no version provided
		if !ok {
			extractedPkg, ok = extractedByName[pkg.Name]
		}

		if !ok {
			continue
		}

		// Copy location and metadata from the extracted package
		packages[key].DepGroups = extractedPkg.DepGroups
		packages[key].BlockLocation = extractedPkg.BlockLocation
		packages[key].NameLocation = extractedPkg.NameLocation
		packages[key].VersionLocation = extractedPkg.VersionLocation
		packages[key].TargetFrameworks = extractedPkg.TargetFrameworks
	}

	return nil
}

var _ lockfile.Matcher = NugetCsprojMatcher{}
