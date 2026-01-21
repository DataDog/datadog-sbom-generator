package rust

import (
	"io"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/Masterminds/semver/v3"
)

// CargoToml represents the structure of a Cargo.toml file
type CargoToml struct {
	Dependencies map[string]interface{} `toml:"dependencies"`
	DevDeps      map[string]interface{} `toml:"dev-dependencies"`
	BuildDeps    map[string]interface{} `toml:"build-dependencies"`
}

func (m CargoTomlMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("Cargo.toml")
}

func (m CargoTomlMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	// Parse the TOML structure to understand what dependencies exist
	var parsed CargoToml
	if err := toml.Unmarshal(content, &parsed); err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// Process each dependency section
	processDependencySection(parsed.Dependencies, packages, lines, sourceFile.Path(), "")
	processDependencySection(parsed.DevDeps, packages, lines, sourceFile.Path(), "dev")
	processDependencySection(parsed.BuildDeps, packages, lines, sourceFile.Path(), "build")

	return nil
}

// processDependencySection cross-references a dependency section from Cargo.toml with the full
// package list from Cargo.lock to add metadata to matching packages.
//
// For each dependency declared in the Cargo.toml section (e.g., [dependencies], [dev-dependencies]),
// it searches through all packages and enriches matching ones with:
//   - IsDirect = true (distinguishes from transitive dependencies)
//   - File positions (BlockLocation, NameLocation, VersionLocation) for the declaration
//   - Dependency group tag (e.g., "dev", "build")
func processDependencySection(deps map[string]interface{}, packages []lockfile.PackageDetails, lines []string, filePath string, depGroup string) {
	if deps == nil {
		return
	}

	// For each dependency in the TOML structure
	for depName, depValue := range deps {
		// Extract version requirement from the dependency value
		versionReq := extractVersionRequirement(depValue)

		// Find matching package from Cargo.lock by name AND version
		// (Cargo.lock can have multiple versions of the same package)
		for key, pkg := range packages {
			if !strings.EqualFold(pkg.Name, depName) {
				continue
			}

			// If we have a version requirement AND package version, check if they match
			if versionReq != "" && pkg.Version != "" && !versionMatches(pkg.Version, versionReq) {
				continue
			}

			// Search for this package name and version in the raw content to get positions
			if found := findPackagePositions(&packages[key], depName, versionReq, lines, filePath); found {
				packages[key].IsDirect = true

				// Set dependency group if specified
				if depGroup != "" {
					packages[key].DepGroups = append(packages[key].DepGroups, depGroup)
				}
			}

			break
		}
	}
}

// extractVersionRequirement extracts the version requirement from a Cargo.toml dependency value.
// The value can be either a string (e.g., "1.0") or a table (e.g., { version = "1.0", features = [...] }).
func extractVersionRequirement(depValue interface{}) string {
	switch v := depValue.(type) {
	case string:
		// Simple form: serde = "1.0"
		return v
	case map[string]interface{}:
		// Table form: serde = { version = "1.0", features = [...] }
		if version, ok := v["version"].(string); ok {
			return version
		}
	}
	return ""
}

// versionMatches checks if a resolved version from Cargo.lock matches a version requirement from Cargo.toml.
// Uses proper semver matching following Cargo's rules. https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html
func versionMatches(resolvedVersion, requirement string) bool {
	// Parse the resolved version from Cargo.lock
	version, err := semver.NewVersion(resolvedVersion)
	if err != nil {
		// If parsing fails, fall back to simple string comparison
		return resolvedVersion == requirement
	}

	// Cargo treats bare versions like "1.2" as "^1.2" (caret requirement)
	constraintStr := requirement
	if len(requirement) == 0 || strings.IndexByte("^~=><", requirement[0]) == -1 {
		constraintStr = "^" + requirement
	}

	// Parse the constraint from Cargo.toml
	constraint, err := semver.NewConstraint(constraintStr)
	if err != nil {
		// If constraint parsing fails, try exact match as fallback
		return resolvedVersion == requirement
	}

	// Check if the version satisfies the constraint
	return constraint.Check(version)
}

// findPackagePositions searches for a package name in the lines and extracts position information.
// If versionReq is provided, it ensures the line contains that specific version requirement.
func findPackagePositions(pkg *lockfile.PackageDetails, depName string, versionReq string, lines []string, filePath string) bool {
	lowerDepName := strings.ToLower(depName)

	for index, line := range lines {
		lineNumber := index + 1
		lowerLine := strings.ToLower(line)
		trimmedLine := strings.TrimSpace(lowerLine)

		// Check if this line contains the dependency declaration
		// Must be exact match: package name followed by whitespace and =
		if strings.HasPrefix(trimmedLine, lowerDepName+" =") || strings.HasPrefix(trimmedLine, lowerDepName+"=") {
			// If we have a version requirement, check that this line contains it
			if versionReq != "" && !strings.Contains(line, "\""+versionReq+"\"") {
				// This line has the package name but different version requirement, keep searching
				continue
			}

			startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
			endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

			pkg.BlockLocation = models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: startColumn, End: endColumn},
				Filename: filePath,
			}

			nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerDepName, lineNumber)
			if nameLocation != nil {
				nameLocation.Filename = filePath
				pkg.NameLocation = nameLocation
			}

			// Try to extract version location
			// Handles both: serde = "1.0" and serde = { version = "1.0" }
			versionLocation := extractCargoVersion([]string{lowerLine}, lineNumber)
			if versionLocation != nil {
				versionLocation.Filename = filePath
				pkg.VersionLocation = versionLocation
			}

			return true
		}
	}

	return false
}

// extractCargoVersion extracts the version string position from a Cargo.toml line
// Handles both formats:
//   - serde = "1.0"
//   - serde = { version = "1.0", features = ["derive"] }
func extractCargoVersion(lines []string, lineNumber int) *models.FilePosition {
	if len(lines) == 0 {
		return nil
	}

	// Try simple format first: serde = "1.0"
	simpleVersionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock(lines, "[^\"]+", lineNumber, "=\\s*\"", "\"")
	if simpleVersionLocation != nil {
		return simpleVersionLocation
	}

	// Try table format: serde = { version = "1.0" }
	tableVersionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock(lines, "[^\"]+", lineNumber, "version\\s*=\\s*\"", "\"")
	if tableVersionLocation != nil {
		return tableVersionLocation
	}

	return nil
}

var _ lockfile.Matcher = CargoTomlMatcher{}
