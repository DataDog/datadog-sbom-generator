package rust

import (
	"io"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// CargoToml represents the structure of a Cargo.toml file
type CargoToml struct {
	Dependencies map[string]interface{} `toml:"dependencies"`
	DevDeps      map[string]interface{} `toml:"dev-dependencies"`
	BuildDeps    map[string]interface{} `toml:"build-dependencies"`
	Workspace    *CargoWorkspace        `toml:"workspace"`
}

type CargoWorkspace struct {
	Dependencies map[string]interface{} `toml:"dependencies"`
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

	// Process workspace dependencies
	if parsed.Workspace != nil {
		processDependencySection(parsed.Workspace.Dependencies, packages, lines, sourceFile.Path(), "")
	}

	return nil
}

// processDependencySection processes a single dependency section from Cargo.toml
func processDependencySection(deps map[string]interface{}, packages []lockfile.PackageDetails, lines []string, filePath string, depGroup string) {
	if deps == nil {
		return
	}

	// For each dependency in the TOML structure
	for depName := range deps {
		// Find matching package in our list
		for key, pkg := range packages {
			if !strings.EqualFold(pkg.Name, depName) {
				continue
			}

			// Search for this package name in the raw content to get positions
			if found := findPackagePositions(&packages[key], depName, lines, filePath); found {
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

// findPackagePositions searches for a package name in the lines and extracts position information
func findPackagePositions(pkg *lockfile.PackageDetails, depName string, lines []string, filePath string) bool {
	lowerDepName := strings.ToLower(depName)

	for index, line := range lines {
		lineNumber := index + 1
		lowerLine := strings.ToLower(line)
		trimmedLine := strings.TrimSpace(lowerLine)

		// Check if this line contains the dependency declaration
		// Must be exact match: package name followed by whitespace and =
		if strings.HasPrefix(trimmedLine, lowerDepName+" =") || strings.HasPrefix(trimmedLine, lowerDepName+"=") {
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
