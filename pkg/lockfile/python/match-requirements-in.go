package python

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m RequirementsInMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	base := filepath.Base(f.Path())
	inFile := strings.TrimSuffix(base, ".txt") + ".in"

	sourceFile, err := f.Open(inFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}

	return sourceFile, nil
}

func (m RequirementsInMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// Build index: normalized name → slice of indices into packages
	packagesByName := make(map[string][]int, len(packages))
	for i, pkg := range packages {
		key := normalizedRequirementName(pkg.Name)
		packagesByName[key] = append(packagesByName[key], i)
	}

	for index, line := range lines {
		lineNumber := index + 1
		trimmedLine := strings.TrimSpace(line)

		// Skip comments, blanks, options (-r, --index-url, etc.), and URLs
		if trimmedLine == "" || isComment(line) || strings.HasPrefix(trimmedLine, "-") || strings.Contains(trimmedLine, "://") {
			continue
		}

		rawName := extractPackageNameFromRequirementsLine(trimmedLine)
		if rawName == "" {
			continue
		}

		normalizedName := normalizedRequirementName(rawName)

		indices, ok := packagesByName[normalizedName]
		if !ok {
			continue
		}

		startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

		for _, key := range indices {
			packages[key].BlockLocation = models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: startColumn, End: endColumn},
				Filename: sourceFile.Path(),
			}

			nameLocation := fileposition.ExtractStringPositionInBlock([]string{line}, rawName, lineNumber)
			if nameLocation != nil {
				nameLocation.Filename = sourceFile.Path()
				packages[key].NameLocation = nameLocation
			}

			versionLocation := fileposition.ExtractStringPositionInBlock([]string{line}, packages[key].Version, lineNumber)
			if versionLocation != nil {
				versionLocation.Filename = sourceFile.Path()
				packages[key].VersionLocation = versionLocation
			} else {
				// Nil out stale version location from the .txt file to avoid
				// mixed file references (block in .in, version in .txt)
				packages[key].VersionLocation = nil
			}

			packages[key].IsDirect = true
		}
	}

	return nil
}

// extractPackageNameFromRequirementsLine extracts the raw package name from a
// requirements line, before any version specifier or extras marker.
// Example: "typing_extensions>=4.0" → "typing_extensions"
// Example: "redis[hiredis]==3.5.3" → "redis"
func extractPackageNameFromRequirementsLine(line string) string {
	for i, c := range line {
		if c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '[' || c == '@' {
			return strings.TrimSpace(line[:i])
		}
	}

	return strings.TrimSpace(line)
}

var _ lockfile.Matcher = RequirementsInMatcher{}
