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

func (m PipfileMatcher) Match(sourcefile lockfile.DepFile, packages []lockfile.PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
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

				packages[key].BlockLocation = models.FilePosition{
					Line:     models.Position{Start: lineNumber, End: lineNumber},
					Column:   models.Position{Start: startColumn, End: endColumn},
					Filename: sourcefile.Path(),
				}

				nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerName, lineNumber)
				if nameLocation != nil {
					nameLocation.Filename = sourcefile.Path()
					packages[key].NameLocation = nameLocation
				}

				versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, ".*", lineNumber, "=\\s*\"", "\"")
				if versionLocation != nil {
					versionLocation.Filename = sourcefile.Path()
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

var _ lockfile.Matcher = PipfileMatcher{}
