package python

import (
	"io"
	"strings"
	"unicode"

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

		manifestKeys, ok := tomlLineKeys(line)
		if !ok {
			continue
		}

		for key, pkg := range packages {
			// There are some libraries that use upper case names, but their name is resolve as lower case (i.e. Django != django)
			lowerName := strings.ToLower(pkg.Name)
			// Compare against the full TOML key(s) rather than a substring match, otherwise a
			// package like "requests" would match a line declaring "requests-oauthlib".
			if !containsLower(manifestKeys, lowerName) {
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

// tomlLineKeys extracts the package name(s) to match from a manifest line. It handles a
// "key = value" TOML line (Pipfile/Poetry), a PEP 621 dependency array item on its own line such
// as `"requests==2.28.0",`, and a PEP 621 inline dependency array such as
// `dependencies = ["requests==2.28.0", "flask>=2.0"]` (pyproject.toml `dependencies = [...]`).
// It is not a full TOML/PEP 508 parser: it only isolates the name(s) so packages are matched
// exactly instead of via substring search.
func tomlLineKeys(line string) ([]string, bool) {
	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
		return nil, false
	}

	if names, ok := pep621InlineArrayNames(trimmedLine); ok {
		return names, true
	}

	if name, ok := pep621ArrayItemName(trimmedLine); ok {
		return []string{name}, true
	}

	key, _, found := strings.Cut(trimmedLine, "=")
	if !found {
		return nil, false
	}

	key = strings.Trim(strings.TrimSpace(key), `"'`)
	if key == "" {
		return nil, false
	}

	return []string{key}, true
}

// containsLower reports whether lowerName is present in names, comparing case-insensitively.
func containsLower(names []string, lowerName string) bool {
	for _, name := range names {
		if strings.ToLower(name) == lowerName {
			return true
		}
	}

	return false
}

// pep621InlineArrayNames extracts package names from a PEP 621 dependency array declared inline
// on a single line, e.g. `dependencies = ["requests==2.28.0", "flask>=2.0"]`. It returns false if
// the line isn't an assignment to a bracketed list closed on the same line, which excludes both
// plain "key = value" lines and the opening line of a multiline array (`dependencies = [`).
func pep621InlineArrayNames(trimmedLine string) ([]string, bool) {
	openIdx := strings.Index(trimmedLine, "[")
	closeIdx := strings.LastIndex(trimmedLine, "]")
	if openIdx == -1 || closeIdx == -1 || closeIdx < openIdx {
		return nil, false
	}

	if !strings.Contains(trimmedLine[:openIdx], "=") {
		return nil, false
	}

	var names []string
	for _, item := range strings.Split(trimmedLine[openIdx+1:closeIdx], ",") {
		if name, ok := pep621ArrayItemName(strings.TrimSpace(item)); ok {
			names = append(names, name)
		}
	}

	return names, len(names) > 0
}

// pep621ArrayItemName extracts the package name from a standalone quoted dependency-array item,
// e.g. `"requests==2.28.0",` or `'flask[async]>=2.0'`. It returns false for anything that isn't
// a single quoted token on the line, including quoted `"key" = "value"` lines, which still need
// to go through the key = value path in tomlLineKey.
func pep621ArrayItemName(trimmedLine string) (string, bool) {
	line := strings.TrimSuffix(trimmedLine, ",")
	if len(line) < 2 {
		return "", false
	}

	quote := line[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	closeIdx := strings.IndexByte(line[1:], quote)
	if closeIdx == -1 {
		return "", false
	}
	closeIdx++

	if strings.TrimSpace(line[closeIdx+1:]) != "" {
		return "", false
	}

	spec := line[1:closeIdx]
	end := strings.IndexFunc(spec, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	name := spec
	if end != -1 {
		name = spec[:end]
	}
	name = strings.TrimSpace(name)

	return name, name != ""
}

// isDevTable checks if the line is a dev dependency table for Poetry, since the implementation is shared as both tools use toml files.
func isDevTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return trimmedLine == "[tool.poetry.dev-dependencies]" || trimmedLine == "[tool.poetry.group.dev.dependencies]"
}

var _ extractor.Matcher = PipfileMatcher{}
