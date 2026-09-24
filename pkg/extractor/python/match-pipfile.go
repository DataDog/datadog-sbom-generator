package python

import (
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m PipfileMatcher) GetSourceFile(depFile extractor.DepFile) (extractor.DepFile, error) {
	return depFile.Open("Pipfile")
}

func (m PipfileMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
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
			continue
		}

		manifestKey, ok := tomlLineKey(line)
		if !ok {
			continue
		}
		lowerManifestKey := strings.ToLower(manifestKey)

		for key, pkg := range packages {
			// There are some libraries that use upper case names, but their name is resolve as lower case (i.e. Django != django)
			lowerName := strings.ToLower(pkg.Name)
			// Compare against the full TOML key rather than a substring match, otherwise a
			// package like "requests" would match a line declaring "requests-oauthlib".
			if lowerManifestKey != lowerName {
				continue
			}

			lowerLine := strings.ToLower(line)
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

	return nil
}

// isTable checks if the line is a table in the Pipfile format.
func isTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")
}

// tomlLineKey extracts the key of a "key = value" TOML line, skipping comments and lines
// without an assignment. It is not a full TOML parser: it only isolates the key so package
// names are matched exactly instead of via substring search.
func tomlLineKey(line string) (string, bool) {
	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
		return "", false
	}

	key, _, found := strings.Cut(trimmedLine, "=")
	if !found {
		return "", false
	}

	key = strings.Trim(strings.TrimSpace(key), `"'`)

	return key, key != ""
}

// isDevTable checks if the line is a dev dependency table for Poetry, since the implementation is shared as both tools use toml files.
func isDevTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return trimmedLine == "[tool.poetry.dev-dependencies]" || trimmedLine == "[tool.poetry.group.dev.dependencies]"
}

var _ extractor.Matcher = PipfileMatcher{}
