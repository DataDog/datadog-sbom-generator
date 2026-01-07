package rust

import (
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m CargoTomlMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("Cargo.toml")
}

func (m CargoTomlMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// Track which dependency section we're currently in
	var currentSection string

	for index, line := range lines {
		lineNumber := index + 1

		// Check if this line starts a new TOML section
		if isTomlSection(line) {
			currentSection = getCargoSection(line)
			continue
		}

		// Only process lines in dependency sections
		if !isCargoDepSection(currentSection) {
			continue
		}

		// Try to match packages against this line
		for key, pkg := range packages {
			lowerLine := strings.ToLower(line)
			lowerName := strings.ToLower(pkg.Name)

			// Check if this line contains the package name
			// Handle both simple format: serde = "1.0"
			// and table format: serde = { version = "1.0" }
			// Must be an exact match: package name followed by whitespace and =
			trimmedLine := strings.TrimSpace(lowerLine)
			if strings.HasPrefix(trimmedLine, lowerName+" =") || strings.HasPrefix(trimmedLine, lowerName+"=") {
				startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
				endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

				packages[key].BlockLocation = models.FilePosition{
					Line:     models.Position{Start: lineNumber, End: lineNumber},
					Column:   models.Position{Start: startColumn, End: endColumn},
					Filename: sourceFile.Path(),
				}

				nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerName, lineNumber)
				if nameLocation != nil {
					nameLocation.Filename = sourceFile.Path()
					packages[key].NameLocation = nameLocation
				}

				// Try to extract version location
				// Handles both: serde = "1.0" and serde = { version = "1.0" }
				versionLocation := extractCargoVersion([]string{lowerLine}, lineNumber)
				if versionLocation != nil {
					versionLocation.Filename = sourceFile.Path()
					packages[key].VersionLocation = versionLocation
				}

				packages[key].IsDirect = true

				// Set dependency groups based on the section
				switch currentSection {
				case "dev-dependencies":
					packages[key].DepGroups = append(packages[key].DepGroups, "dev")
				case "build-dependencies":
					packages[key].DepGroups = append(packages[key].DepGroups, "build")
				default:
					// Regular dependencies - no special group
				}
			}
		}
	}

	return nil
}

// isTomlSection checks if the line is a TOML section header like [dependencies]
func isTomlSection(line string) bool {
	trimmedLine := strings.TrimSpace(line)
	return strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")
}

// getCargoSection extracts the section name from a TOML section header
func getCargoSection(line string) string {
	trimmedLine := strings.TrimSpace(line)
	// Remove [ and ]
	section := strings.TrimPrefix(trimmedLine, "[")
	section = strings.TrimSuffix(section, "]")

	return strings.ToLower(section)
}

// isCargoDepSection checks if the section is a Cargo dependency section
func isCargoDepSection(section string) bool {
	return section == "dependencies" ||
		section == "dev-dependencies" ||
		section == "build-dependencies" ||
		section == "workspace.dependencies"
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
