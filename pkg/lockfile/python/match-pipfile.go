package python

import (
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m PipfileMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("Pipfile")
}

func (m PipfileMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// In poetry, if the table name is [tool.poetry.dev-dependencies] or [tool.poetry.group.dev.dependencies],
	// then the dependencies under this table are dev dependencies.
	// Otherwise, they are regular dependencies
	var inDevDepTable bool

	for index, line := range lines {
		lineNumber := index + 1

		// if this is the start of a new table, check if it's a table that can contain dev dependencies
		if isTable(line) {
			inDevDepTable = isDevTable(line)
		}

		for key, pkg := range packages {
			// There are some libraries that use upper case names, but their name is resolve as lower case (i.e. Django != django)
			lowerLine := strings.ToLower(line)
			lowerName := strings.ToLower(pkg.Name)
			// We only need to find the package name because there cannot be multiple entries of the same dependency in the source file nor the lock file
			if strings.Contains(lowerLine, lowerName) {
				startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
				endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

				packages[key].LocationRole = models.LocationRoleManifest
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

				versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, ".*", lineNumber, "=\\s*\"", "\"")
				if versionLocation != nil {
					versionLocation.Filename = sourceFile.Path()
					packages[key].VersionLocation = versionLocation
				}

				packages[key].IsDirect = true

				if inDevDepTable {
					packages[key].DepGroups = append(packages[key].DepGroups, "dev")
				}
			}
		}
	}

	return nil
}

// isTable checks if the line is a table in the Pipfile format.
func isTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")
}

// isDevTable checks if the line is a dev dependency table for Poetry, since the implementation is shared as both tools use toml files.
func isDevTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return trimmedLine == "[tool.poetry.dev-dependencies]" || trimmedLine == "[tool.poetry.group.dev.dependencies]"
}

var _ lockfile.Matcher = PipfileMatcher{}
